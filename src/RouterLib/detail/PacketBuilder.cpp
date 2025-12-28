#include "PacketBuilder.h"

#include <algorithm>
#include <cstring>

#include "utils.h"      // cksum, make_mac_addr
#include "protocol.h"

// small helpers

static void fill_eth_hdr(sr_ethernet_hdr_t* eth,
                         const mac_addr& src,
                         const mac_addr& dst,
                         uint16_t ether_type)
{
    std::memcpy(eth->ether_shost, src.data(), ETHER_ADDR_LEN);
    std::memcpy(eth->ether_dhost, dst.data(), ETHER_ADDR_LEN);
    eth->ether_type = htons(ether_type);
}

static void fill_ip_hdr(sr_ip_hdr_t* ip,
                        uint32_t src_ip,
                        uint32_t dst_ip,
                        uint16_t payload_len,
                        uint8_t proto)
{
    ip->ip_v   = 4;
    ip->ip_hl  = 5; // 5 * 4 = 20 bytes
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(sr_ip_hdr_t) + payload_len);
    ip->ip_id  = 0;
    ip->ip_off = htons(0);
    ip->ip_ttl = INIT_TTL;
    ip->ip_p   = proto;
    ip->ip_src = src_ip;
    ip->ip_dst = dst_ip;
    ip->ip_sum = 0;
    ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
}

// Copy original IP header + up to 8 bytes of payload into ICMP "data" field
// (total up to ICMP_DATA_SIZE bytes).
static void fill_icmp_t3_data(sr_icmp_t3_hdr_t* icmp,
                              const Packet& original)
{
    if (original.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        std::memset(icmp->data, 0, ICMP_DATA_SIZE);
        return;
    }

    const auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(
        original.data() + sizeof(sr_ethernet_hdr_t)
    );

    const uint8_t* orig_ip_start =
        reinterpret_cast<const uint8_t*>(orig_ip);

    const std::size_t bytes_available =
        original.size() - sizeof(sr_ethernet_hdr_t);

    const uint16_t ip_total_len = ntohs(orig_ip->ip_len);

    const std::size_t to_copy = std::min<std::size_t>(
        ICMP_DATA_SIZE,
        std::min<std::size_t>(ip_total_len, bytes_available)
    );

    std::memset(icmp->data, 0, ICMP_DATA_SIZE);
    std::memcpy(icmp->data, orig_ip_start, to_copy);
}

// public builders 

Packet build_icmp_type3(const Packet& original,
                        uint8_t code,
                        const RoutingInterface& out_iface)
{
    if (original.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return {};
    }

    const auto* orig_eth = reinterpret_cast<const sr_ethernet_hdr_t*>(
        original.data()
    );
    const auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(
        original.data() + sizeof(sr_ethernet_hdr_t)
    );

    Packet pkt(sizeof(sr_ethernet_hdr_t)
             + sizeof(sr_ip_hdr_t)
             + sizeof(sr_icmp_t3_hdr_t));

    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
    auto* ip  = reinterpret_cast<sr_ip_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t)
    );
    auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
    );

    // Ethernet: src = our iface MAC, dst = original src MAC
    mac_addr dst_mac = make_mac_addr((void*)orig_eth->ether_shost);
    fill_eth_hdr(eth, out_iface.mac, dst_mac, ethertype_ip);

    // IP: src = our iface IP, dst = original IP source
    fill_ip_hdr(ip, out_iface.ip, orig_ip->ip_src,
                sizeof(sr_icmp_t3_hdr_t), ip_protocol_icmp);

    icmp->icmp_type = 3;      // Destination Unreachable
    icmp->icmp_code = code;   // net(0), host(1), port(3), etc.
    icmp->unused    = 0;
    icmp->next_mtu  = 0;

    fill_icmp_t3_data(icmp, original);

    icmp->icmp_sum = 0;
    icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

    return pkt;
}

Packet build_icmp_time_exceeded(const Packet& original,
                                const RoutingInterface& out_iface)
{
    if (original.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return {};
    }

    const auto* orig_eth = reinterpret_cast<const sr_ethernet_hdr_t*>(
        original.data()
    );
    const auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(
        original.data() + sizeof(sr_ethernet_hdr_t)
    );

    Packet pkt(sizeof(sr_ethernet_hdr_t)
             + sizeof(sr_ip_hdr_t)
             + sizeof(sr_icmp_t3_hdr_t));

    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
    auto* ip  = reinterpret_cast<sr_ip_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t)
    );
    auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
    );

    // Ethernet: src = our iface, dst = original src MAC
    mac_addr dst_mac = make_mac_addr((void*)orig_eth->ether_shost);
    fill_eth_hdr(eth, out_iface.mac, dst_mac, ethertype_ip);

    // IP: src = our iface, dst = original IP source
    fill_ip_hdr(ip, out_iface.ip, orig_ip->ip_src,
                sizeof(sr_icmp_t3_hdr_t), ip_protocol_icmp);

    icmp->icmp_type = 11;   // Time Exceeded
    icmp->icmp_code = 0;    // TTL exceeded in transit
    icmp->unused    = 0;
    icmp->next_mtu  = 0;

    fill_icmp_t3_data(icmp, original);

    icmp->icmp_sum = 0;
    icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

    return pkt;
}

Packet build_icmp_echo_reply(const Packet& original,
                             const RoutingInterface& out_iface)
{
    if (original.size() < sizeof(sr_ethernet_hdr_t)
                        + sizeof(sr_ip_hdr_t)
                        + sizeof(sr_icmp_hdr_t)) {
        return {};
    }

    const auto* orig_eth = reinterpret_cast<const sr_ethernet_hdr_t*>(
        original.data()
    );
    const auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(
        original.data() + sizeof(sr_ethernet_hdr_t)
    );

    // Calculate ICMP payload length from IP total length
    const uint16_t ip_total_len = ntohs(orig_ip->ip_len);
    if (ip_total_len < sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
        return {};
    }
    const uint16_t icmp_len = ip_total_len - sizeof(sr_ip_hdr_t);

    const auto* orig_icmp = reinterpret_cast<const sr_icmp_hdr_t*>(
        original.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
    );

    Packet pkt(sizeof(sr_ethernet_hdr_t)
             + sizeof(sr_ip_hdr_t)
             + icmp_len);

    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
    auto* ip  = reinterpret_cast<sr_ip_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t)
    );
    auto* new_icmp = reinterpret_cast<sr_icmp_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)
    );

    // Ethernet: src = our iface MAC, dst = original src MAC
    mac_addr dst_mac = make_mac_addr((void*)orig_eth->ether_shost);
    fill_eth_hdr(eth, out_iface.mac, dst_mac, ethertype_ip);

    // IP: src = our iface IP, dst = original IP source
    fill_ip_hdr(ip, out_iface.ip, orig_ip->ip_src,
                icmp_len, ip_protocol_icmp);

    // Copy original ICMP header + data
    std::memcpy(reinterpret_cast<uint8_t*>(new_icmp),
                reinterpret_cast<const uint8_t*>(orig_icmp),
                icmp_len);

    // Turn it into an echo reply
    new_icmp->icmp_type = 0; // Echo Reply
    new_icmp->icmp_code = 0;
    new_icmp->icmp_sum  = 0;
    new_icmp->icmp_sum  = cksum(new_icmp, icmp_len);

    return pkt;
}

// Helper: clamp how much of the original IP packet we copy into ICMP data
static void fillIcmpDataFromOriginal(sr_icmp_t3_hdr_t* icmp,
                                     const Packet& original,
                                     const sr_ip_hdr_t* orig_ip)
{
    const uint8_t* orig_ip_start =
        reinterpret_cast<const uint8_t*>(orig_ip);

    uint16_t orig_ip_len = ntohs(orig_ip->ip_len);
    // bytes of IP payload actually present in the original packet buffer
    size_t bytes_after_ip =
        original.size() - sizeof(sr_ethernet_hdr_t);

    size_t max_copy = std::min<std::size_t>(
        ICMP_DATA_SIZE,
        std::min<std::size_t>(orig_ip_len, bytes_after_ip)
    );

    std::memset(icmp->data, 0, ICMP_DATA_SIZE);
    std::memcpy(icmp->data, orig_ip_start, max_copy);
}

Packet buildIcmpHostUnreachable(const Packet& original,
                                const RoutingInterface& out_iface)
{
    // Need at least Ethernet + IP header in the original
    if (original.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        return {};
    }

    const auto* orig_eth = reinterpret_cast<const sr_ethernet_hdr_t*>(
        original.data());
    const auto* orig_ip  = reinterpret_cast<const sr_ip_hdr_t*>(
        original.data() + sizeof(sr_ethernet_hdr_t));

    // Allocate Ethernet + IP + ICMP type 3
    Packet pkt(sizeof(sr_ethernet_hdr_t) +
               sizeof(sr_ip_hdr_t) +
               sizeof(sr_icmp_t3_hdr_t));

    auto* eth  = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
    auto* ip   = reinterpret_cast<sr_ip_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t));
    auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(
        pkt.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    //  Ethernet header 
    // dest MAC = original source MAC
    std::memcpy(eth->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
    // src MAC = our outgoing interface MAC
    std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_ip);

    //  IP header 
    ip->ip_v   = 4;
    ip->ip_hl  = 5; // 5 * 4 = 20 bytes
    ip->ip_tos = 0;
    ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ip->ip_id  = 0;
    ip->ip_off = htons(0);
    ip->ip_ttl = INIT_TTL;
    ip->ip_p   = ip_protocol_icmp;
    ip->ip_sum = 0;
    ip->ip_src = out_iface.ip;      // already in network order
    ip->ip_dst = orig_ip->ip_src;   // send back to original source

    ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));

    //  ICMP header + data 
    std::memset(icmp, 0, sizeof(sr_icmp_t3_hdr_t));
    icmp->icmp_type = 3; // Destination Unreachable
    icmp->icmp_code = 1; // Host Unreachable
    icmp->unused    = 0;
    icmp->next_mtu  = 0;

    // Per spec: data = original IP header + first 8 bytes of payload
    fillIcmpDataFromOriginal(icmp, original, orig_ip);

    icmp->icmp_sum = 0;
    icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

    return pkt;
}

