#pragma once
#include "../RouterTypes.h"
#include "protocol.h"
#include "utils.h"
#include "../IRoutingTable.h"

// Build full Ethernet+IP+ICMP Type 3 (Destination Unreachable) packet.
// code: 0 = net unreachable, 1 = host unreachable, 3 = port unreachable, etc.
Packet build_icmp_type3(const Packet& original,
                        uint8_t code,
                        const RoutingInterface& out_iface);

// Build full Ethernet+IP+ICMP Time Exceeded (type 11, code 0) packet.
Packet build_icmp_time_exceeded(const Packet& original,
                                const RoutingInterface& out_iface);

// Build full Ethernet+IP+ICMP Echo Reply (type 0) in response to an
// ICMP echo request sent *to* one of our router interfaces.
Packet build_icmp_echo_reply(const Packet& original,
                             const RoutingInterface& out_iface);

Packet build_ip_packet(const RoutingInterface& src,
                       uint32_t dst_ip,
                       uint8_t protocol,
                       const uint8_t* payload,
                       size_t payload_len);

Packet build_eth_frame(const mac_addr& src,
                       const mac_addr& dst,
                       uint16_t ethertype,
                       const uint8_t* payload,
                       size_t payload_len);

// Build an ICMP Destination Host Unreachable (type 3, code 1) packet
// responding to `original`, using `out_iface` as the source interface.
Packet buildIcmpHostUnreachable(const Packet& original,
                                const RoutingInterface& out_iface);

                                