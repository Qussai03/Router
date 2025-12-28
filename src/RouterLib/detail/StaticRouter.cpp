#pragma once

#include <memory>
#include <string>
#include <vector>
#include <mutex>

#include "../RouterTypes.h"
#include "../IRoutingTable.h"
#include "../IPacketSender.h"
#include "protocol.h" 

#include "StaticRouter.h"
#include <arpa/inet.h>
#include <spdlog/spdlog.h>
#include <cstring>
#include "utils.h"
#include "PacketBuilder.h"

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache, 
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
    , packetSender(packetSender)
    , arpCache(std::move(arpCache))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("packet is too small to contain an ethernet header");
        return;
    }

    sr_ethernet_hdr_t eth_hdr{};
    std::memcpy(&eth_hdr, packet.data(), sizeof(sr_ethernet_hdr_t));
    uint16_t ether_type = ntohs(eth_hdr.ether_type);

    if (ether_type == ethertype_ip) {
        handleIp(packet, iface);
    } else if (ether_type == ethertype_arp) {
        handleArp(packet, iface);
    } else {
        // not ip or arp, we just drop it
        spdlog::debug("dropping packet with unknown ethertype: 0x{:04x}", ether_type);
    }
}


void StaticRouter::handleArp(Packet& packet, const std::string& iface) {

    // TODO: fix these to no longer be nullptrs
    sr_ethernet_hdr_t *eth = nullptr;
    sr_arp_hdr_t *arp = nullptr;

    if(!parseArpHeaders(packet, eth, arp)) {
        return;
    }

    if(ntohs(arp->ar_hrd) != arp_hrd_ethernet || ntohs(arp->ar_pro) != ethertype_ip) {
        return;
    }


    uint16_t op = ntohs(arp->ar_op);
    if(op == arp_op_request) {
        handleArpRequest(eth, arp, iface);
    } else if(op == arp_op_reply) {
        handleArpReply(arp);
    } 

}

void StaticRouter::handleArpRequest(sr_ethernet_hdr_t* eth, sr_arp_hdr_t* arp, const std::string& iface) {
    ip_addr target_ip = arp->ar_tip;

    // find which interface (if any) owns this ip
    const RoutingInterface* my_iface = findInterfaceByIp(target_ip);
    if (!my_iface) {
        // not for us
        return;
    }

    // per spec: ignore arp requests for our ip that arrive on wrong iface
    if (my_iface->name != iface) {
        return;
    }

     // build arp reply
    Packet reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    auto* r_eth = reinterpret_cast<sr_ethernet_hdr_t*>(reply.data());
    auto* r_arp = reinterpret_cast<sr_arp_hdr_t*>(
        reply.data() + sizeof(sr_ethernet_hdr_t)
    );

    // ethernet hader: dest = sender mac, src= our mac 
    std::memcpy(r_eth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
    std::memcpy(r_eth->ether_shost, my_iface->mac.data(), ETHER_ADDR_LEN);
     r_eth->ether_type = htons(ethertype_arp);

    // arp header
    r_arp->ar_hrd = htons(arp_hrd_ethernet);
    r_arp->ar_pro = htons(ethertype_ip);
    r_arp->ar_hln = ETHER_ADDR_LEN;
    r_arp->ar_pln = 4;
    r_arp->ar_op  = htons(arp_op_reply);

    // sender = us
    std::memcpy(r_arp->ar_sha, my_iface->mac.data(), ETHER_ADDR_LEN);
    r_arp->ar_sip = my_iface->ip;

    // target = original sender
    std::memcpy(r_arp->ar_tha, arp->ar_sha, ETHER_ADDR_LEN);
    r_arp->ar_tip = arp->ar_sip;

    packetSender->sendPacket(reply, iface);
}

void StaticRouter::handleArpReply(sr_arp_hdr_t* arp) {
    ip_addr sender_ip = arp->ar_sip;
    mac_addr sender_mac = make_mac_addr(arp->ar_sha);

    arpCache->addEntry(sender_ip, sender_mac);
}

bool StaticRouter::parseIpHeaders(Packet& packet, sr_ethernet_hdr_t*& eth, sr_ip_hdr_t*& ip) {
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        spdlog::error("ip packet too small");
        return false;
    }

    eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    ip = reinterpret_cast<sr_ip_hdr_t*>(
        packet.data() + sizeof(sr_ethernet_hdr_t)
    );
    return true;
}

void StaticRouter::handleIp(Packet& packet, const std::string& in_iface) {
    // Snapshot of how the packet looked on the wire, before we touch TTL/checksum.
    Packet original = packet;

    sr_ethernet_hdr_t* eth = nullptr;
    sr_ip_hdr_t* ip = nullptr;

    if (!parseIpHeaders(packet, eth, ip)) {
        return;
    }

    // validate checksum, decrement TTL, possibly send Time Exceeded
    if (!validateAndUpdateTtl(ip, in_iface, packet, original)) {
        return;
    }

    const RoutingInterface* local_iface = nullptr;
    if (packetIsForRouter(ip, local_iface)) {
        handleIpToRouter(packet, in_iface, *local_iface, original);
    } else {
        handleIpForward(packet, in_iface, original);
    }
}

bool StaticRouter::validateAndUpdateTtl(sr_ip_hdr_t* ip,
                                        const std::string& in_iface,
                                        Packet& packet,
                                        const Packet& original) {
    // verify checksum over ip header
    // verify checksum over ip header
    uint16_t old_sum = ip->ip_sum;

    ip->ip_sum = 0;
    uint16_t calc = cksum(ip, sizeof(sr_ip_hdr_t));

    if (calc != old_sum) {
        spdlog::debug("dropping packet: bad ip checksum: calc={}, old={}", calc, old_sum);
        return false;
    }

    // if ttl is somehow zero before we decrement it we should not do anything with it
    if (ip->ip_ttl == 0) {
        return false;
    }

    ip->ip_ttl--;

    if (ip->ip_ttl == 0) {
        // TTL expired because of us -> ICMP Time Exceeded (type 11, code 0)
        // Choose outgoing interface based on route to the original source IP.
        ip_addr src_ip = ip->ip_src;

        std::string sendIface = in_iface;
        RoutingInterface out_iface = routingTable->getRoutingInterface(in_iface);

        auto route_opt = routingTable->getRoutingEntry(src_ip);
        if (route_opt.has_value()) {
            const auto& route = route_opt.value();
            out_iface = routingTable->getRoutingInterface(route.iface);
            sendIface = route.iface;
        }

        // Use the original packet as received on the wire
        Packet icmp = build_icmp_time_exceeded(original, out_iface);
        if (!icmp.empty()) {
            packetSender->sendPacket(icmp, sendIface);
        }
        return false;
    }

    // recompute checksum over modified header
    ip->ip_sum = 0;
    ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
    return true;
}


bool StaticRouter::packetIsForRouter(sr_ip_hdr_t* ip, const RoutingInterface*& local_iface) {
    // ip_dst is already in network byte order; RoutingInterface::ip is too.
    ip_addr dst = ip->ip_dst;
    const auto& ifaces = routingTable->getRoutingInterfaces();

    for (const auto& kv : ifaces) {
        const auto& ri = kv.second;
        if (ri.ip == dst) {
            local_iface = &ri;
            return true;
        }
    }
    return false;
}

void StaticRouter::handleIpToRouter(Packet& packet,
                                    const std::string& in_iface,
                                    const RoutingInterface& local_iface,
                                    const Packet& original) {
    sr_ethernet_hdr_t* eth = nullptr;
    sr_ip_hdr_t* ip = nullptr;
    if (!parseIpHeaders(packet, eth, ip)) {
        return;
    }

    uint8_t proto = ip->ip_p;

    if (proto == ip_protocol_icmp) {
        // ICMP to one of our IPs: handle echo request
        if (packet.size() < sizeof(sr_ethernet_hdr_t)
                          + sizeof(sr_ip_hdr_t)
                          + sizeof(sr_icmp_hdr_t)) {
            return;
        }

        auto* icmp = reinterpret_cast<sr_icmp_hdr_t*>(
            packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
        );

        // Validate ICMP checksum
        uint16_t ip_total_len = ntohs(ip->ip_len);
        if (ip_total_len < sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
            return;
        }

        // ICMP length is the rest of the IP payload (not the IP header itself)
        uint16_t icmp_len = ip_total_len - sizeof(sr_ip_hdr_t);

        uint16_t old_sum = icmp->icmp_sum;
        icmp->icmp_sum = 0;
        uint16_t calc = cksum(icmp, icmp_len);
        if (calc != old_sum) {
            spdlog::debug("dropping icmp to router: bad checksum");
            return;
        }

        // Echo request?
        if (icmp->icmp_type == 8) { // Echo Request
            ip_addr src_ip = ip->ip_src;

            // Default: reply out the incoming iface using that iface's config
            RoutingInterface out_iface = local_iface;
            std::string sendIface = in_iface;

            // If we have a route back to the source host, use that iface instead
            auto route_opt = routingTable->getRoutingEntry(src_ip);
            if (route_opt.has_value()) {
                const auto& route = route_opt.value();
                out_iface = routingTable->getRoutingInterface(route.iface);
                sendIface = route.iface;
            }

            // Build reply using that outgoing interface's MAC/etc.
            Packet reply = build_icmp_echo_reply(original, out_iface);
            if (!reply.empty()) {
                // BUT: the IP source must be the IP we were addressed on
                // (local_iface.ip), not necessarily out_iface.ip.
                auto* rep_ip = reinterpret_cast<sr_ip_hdr_t*>(
                    reply.data() + sizeof(sr_ethernet_hdr_t)
                );
                rep_ip->ip_src = local_iface.ip;
                rep_ip->ip_sum = 0;
                rep_ip->ip_sum = cksum(rep_ip, sizeof(sr_ip_hdr_t));

                packetSender->sendPacket(reply, sendIface);
            }
        }

        return;
    }

    if (proto == ip_protocol_tcp || proto == ip_protocol_udp) {
        // TCP/UDP to router -> ICMP Port Unreachable (type 3, code 3)
        ip_addr src_ip = ip->ip_src;

        RoutingInterface out_iface = local_iface;
        std::string sendIface = in_iface;

        auto route_opt = routingTable->getRoutingEntry(src_ip);
        if (route_opt.has_value()) {
            const auto& route = route_opt.value();
            out_iface = routingTable->getRoutingInterface(route.iface);
            sendIface = route.iface;
        }

        Packet icmp = build_icmp_type3(original, 3, out_iface);
        if (!icmp.empty()) {
            auto* rep_ip = reinterpret_cast<sr_ip_hdr_t*>(
                icmp.data() + sizeof(sr_ethernet_hdr_t)
            );
            rep_ip->ip_src = local_iface.ip;
            rep_ip->ip_sum = 0;
            rep_ip->ip_sum = cksum(rep_ip, sizeof(sr_ip_hdr_t));

            packetSender->sendPacket(icmp, sendIface);
        }
        return;
    }

    // Otherwise: ignore
}

void StaticRouter::handleIpForward(Packet& packet,
                                   const std::string& in_iface,
                                   const Packet& original)
{
    // assume validateAndUpdateTtl has already run on packet
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto* ip  = reinterpret_cast<sr_ip_hdr_t*>(
        packet.data() + sizeof(sr_ethernet_hdr_t)
    );

    ip_addr dst = ip->ip_dst;  // network byte order

    // longest prefix match in routing table
    auto route_opt = routingTable->getRoutingEntry(dst);
    if (!route_opt.has_value()) {
        // no route: ICMP destination network unreachable (type 3, code 0)
        // using the original, unmodified packet for the embedded header
        RoutingInterface out_iface = routingTable->getRoutingInterface(in_iface);
        Packet icmp = build_icmp_type3(original, 0, out_iface);
        if (!icmp.empty()) {
            packetSender->sendPacket(icmp, in_iface);
        }
        return;
    }

    const RoutingEntry& route = *route_opt;

    // next-hop IP: either the gateway or the destination itself if gateway == 0.
    ip_addr next_hop_ip = (route.gateway == 0) ? dst : route.gateway;

    // outgoing interface from the routing entry.
    RoutingInterface out_iface = routingTable->getRoutingInterface(route.iface);

    // check ARP cache for next-hop MAC.
    auto mac_opt = arpCache->getEntry(next_hop_ip);
    if (mac_opt.has_value()) {
        mac_addr nh_mac = mac_opt.value();

        // fill in eth header and send.
        std::memcpy(eth->ether_dhost, nh_mac.data(), ETHER_ADDR_LEN);
        std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);

        packetSender->sendPacket(packet, out_iface.name);
        return;
    }

    // ARP miss: queue a copy of the ORIGINAL packet (as received on the wire)
    // this is what the ICMP Destination Host Unreachable tests expect to see embedded inside the ICMP Type 3 payload
    arpCache->queuePacket(next_hop_ip, original, out_iface.name);
}



bool StaticRouter::parseArpHeaders(Packet& packet,
                                   sr_ethernet_hdr_t*& eth,
                                   sr_arp_hdr_t*& arp) {
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        spdlog::error("arp packet too small");
        return false;
    }

    eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    arp = reinterpret_cast<sr_arp_hdr_t*>(
        packet.data() + sizeof(sr_ethernet_hdr_t)
    );
    return true;
}

// helper to find which interface owns an ip
const RoutingInterface* StaticRouter::findInterfaceByIp(ip_addr ip) {
    const auto& ifaces = routingTable->getRoutingInterfaces();
    for (const auto& [name, ri] : ifaces) {
        if (ri.ip == ip) {
            return &ri;
        }
    }
    return nullptr;
}
