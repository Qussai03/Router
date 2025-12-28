#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"
#include "PacketBuilder.h"
#include "../IRoutingTable.h"

// helper to build AND SEND arp request packet
void ArpCache::sendArpRequest(const std::string& iface, ip_addr targetIp) {
    // Look up outgoing interface for this name
    RoutingInterface out_iface = routingTable->getRoutingInterface(iface);

    // Allocate Ethernet + ARP header
    Packet pkt(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    std::memset(pkt.data(), 0, pkt.size());

    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
    auto* arp = reinterpret_cast<sr_arp_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t)
    );

    // Ethernet header: broadcast ARP request
    std::memset(eth->ether_dhost, 0xFF, ETHER_ADDR_LEN);                  // dest = broadcast
    std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);  // src = iface MAC
    eth->ether_type = htons(ethertype_arp);

    // ARP header
    arp->ar_hrd = htons(arp_hrd_ethernet);
    arp->ar_pro = htons(ethertype_ip);
    arp->ar_hln = ETHER_ADDR_LEN;
    arp->ar_pln = 4;
    arp->ar_op  = htons(arp_op_request);

    // sender = this router's interface
    std::memcpy(arp->ar_sha, out_iface.mac.data(), ETHER_ADDR_LEN);
    arp->ar_sip = out_iface.ip;

    // target = next-hop IP we are resolving
    std::memset(arp->ar_tha, 0x00, ETHER_ADDR_LEN);
    arp->ar_tip = targetIp;

    packetSender->sendPacket(pkt, iface);
}

ArpCache::ArpCache(
    std::chrono::milliseconds entryTimeout, 
    std::chrono::milliseconds tickInterval, 
    std::chrono::milliseconds resendInterval,
    std::shared_ptr<IPacketSender> packetSender, 
    std::shared_ptr<IRoutingTable> routingTable)
: entryTimeout(entryTimeout)
, tickInterval(tickInterval)
, resendInterval(resendInterval)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);

    auto now = std::chrono::steady_clock::now();

    // walk all pending ARP requests
    for (auto it = pending.begin(); it != pending.end(); ) {
        ip_addr ip = it->first;
        ArpRequest& req = it->second;

        // only act if it's time to retry
        if (now - req.lastSent >= resendInterval) {
            if (req.numARPS >= 7) {
                // sent 7 ARPs with no reply -> send ICMP destination host unreachable
                while (!req.waitingPackets.empty()) {
                    QueuedPacket qp = req.waitingPackets.front();
                    req.waitingPackets.pop();

                    if (qp.packet.size() <
                        sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
                        continue;
                    }

                    auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(
                        qp.packet.data() + sizeof(sr_ethernet_hdr_t));
                    ip_addr src_ip = orig_ip->ip_src;

                    // default outgoing interface: the iface we originally planned to send on
                    RoutingInterface out_iface =
                        routingTable->getRoutingInterface(qp.iface);
                    std::string sendIface = qp.iface;

                    // prefer routing decision based on the original source IP
                    auto route_opt = routingTable->getRoutingEntry(src_ip);
                    if (route_opt.has_value()) {
                        const auto& route = route_opt.value();
                        out_iface = routingTable->getRoutingInterface(route.iface);
                        sendIface = route.iface;
                    }

                    Packet icmp = build_icmp_type3(qp.packet, /*code=*/1, out_iface);
                    if (!icmp.empty()) {
                        packetSender->sendPacket(icmp, sendIface);
                    }
                }

                // remove this pending ARP request
                it = pending.erase(it);
                continue;
            }

            // otherisw we have to resend ARP
            req.numARPS++;
            req.lastSent = now;

            if (!req.waitingPackets.empty()) {
                const QueuedPacket& first = req.waitingPackets.front();
                const std::string& iface = first.iface;

                // resend a broadcast ARP on the same interface
                sendArpRequest(iface, ip);
            }
        }

        ++it;
    }

    // exp ARP cache entries
    auto now2 = std::chrono::steady_clock::now();
    for (auto it = entries.begin(); it != entries.end(); ) {
        const auto& entry = it->second;
        if (now2 - entry.timeAdded >= entryTimeout) {
            it = entries.erase(it);
        } else {
            ++it;
        }
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    if (entries.count(ip)) {
        return entries[ip].mac;
    }

    return std::nullopt;
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // TRYING THIS INSTEAD ... only accept ARP replies we actually asked for
    auto it = pending.find(ip);
    if (it == pending.end()) {
        // unsolicited / random ARP reply -> ignore
        return;
    }

    // store / update the ARP cache entry
    ArpEntry entry;
    entry.mac = mac;
    entry.timeAdded = std::chrono::steady_clock::now();
    entries[ip] = entry;

    // we DID have a pending ARP request so still flush queued packets
    ArpRequest& req = it->second;

    while (!req.waitingPackets.empty()) {
        QueuedPacket qp = req.waitingPackets.front();
        req.waitingPackets.pop();

        Packet out = qp.packet;
        auto *eth = reinterpret_cast<sr_ethernet_hdr_t *>(out.data());

        // dest MAC = newly-learned MAC
        std::memcpy(eth->ether_dhost, mac.data(), ETHER_ADDR_LEN);

        // src MAC = MAC of the outgoing interface
        RoutingInterface out_iface =
            routingTable->getRoutingInterface(qp.iface);
        std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);

        // send out the correct interface
        packetSender->sendPacket(out, qp.iface);
    }

    pending.erase(it);
}


void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    // get or create the pending request for this IP
    ArpRequest& req = pending[ip];

    // queue the packet for later
    req.waitingPackets.emplace(QueuedPacket{packet, iface});

    // if this is the first ARP attempt for this IP, send an ARP now
    if (req.numARPS == 0) {
        req.lastSent = std::chrono::steady_clock::now();
        req.numARPS = 1;

        // always send a fresh, broadcast ARP out this interface
        sendArpRequest(iface, ip);
    }
}