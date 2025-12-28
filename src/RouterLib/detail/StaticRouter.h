#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>
#include <memory>
#include <mutex>

#include "ArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "IStaticRouter.h"
#include "protocol.h" 
class StaticRouter : public IStaticRouter {
public:
    StaticRouter(
        std::unique_ptr<ArpCache> arpCache, 
        std::shared_ptr<IRoutingTable> routingTable,
        std::shared_ptr<IPacketSender> packetSender);

    virtual void handlePacket(std::vector<uint8_t> packet, std::string iface) override;
    // helpers for arp
    void handleArp(Packet& packet, const std::string& iface);
    bool parseArpHeaders(Packet& packet,
                         sr_ethernet_hdr_t*& eth,
                         sr_arp_hdr_t*& arp);
    const RoutingInterface* findInterfaceByIp(ip_addr ip);
    void handleArpRequest(sr_ethernet_hdr_t* eth,
                          sr_arp_hdr_t* arp,
                          const std::string& iface);
    void handleArpReply(sr_arp_hdr_t* arp);

    // helpers for ip
    void handleIp(Packet& packet, const std::string& in_iface);
    bool parseIpHeaders(Packet& packet,
                        sr_ethernet_hdr_t*& eth,
                        sr_ip_hdr_t*& ip);
   bool validateAndUpdateTtl(sr_ip_hdr_t* ip,
                              const std::string& in_iface,
                              Packet& packet,
                              const Packet& original);
    bool packetIsForRouter(sr_ip_hdr_t* ip,
                           const RoutingInterface*& local_iface);
    void handleIpToRouter(Packet& packet,
                          const std::string& in_iface,
                          const RoutingInterface& local_iface,
                          const Packet& original);
    void handleIpForward(Packet& packet,
                         const std::string& in_iface,
                         const Packet& original);

private:
    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<ArpCache> arpCache;
};

#endif //STATICROUTER_H
