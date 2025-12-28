#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <chrono>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>
#include <queue>

#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"

struct ArpEntry {
    std::chrono::steady_clock::time_point timeAdded;
    // DONE: Complete
    mac_addr mac; // the MAC address resolved for this IP
};

// made these 2 sstructs and added in 

struct QueuedPacket {
    Packet packet;
    std::string iface;
};

struct ArpRequest {
    std::chrono::steady_clock::time_point lastSent;
    int numARPS = 0;
    std::queue<QueuedPacket> waitingPackets;
};

class ArpCache {
public:
    ArpCache(
        std::chrono::milliseconds entryTimeout,
        std::chrono::milliseconds tickInterval,
        std::chrono::milliseconds resendInterval,
        std::shared_ptr<IPacketSender> packetSender, 
        std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache();

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac);

    std::optional<mac_addr> getEntry(uint32_t ip);

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface);

private:
    void loop();
    void sendArpRequest(const std::string& iface, ip_addr targetIp);

    std::chrono::milliseconds entryTimeout;
    std::chrono::milliseconds tickInterval;
    std::chrono::milliseconds resendInterval;

    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::mutex mutex;
    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;
    
    std::unordered_map<ip_addr, ArpEntry> entries;
    // associates IP addrs of unresolved ARP requests to their corresponding request
    std::unordered_map<ip_addr, ArpRequest> pending; 
};



#endif //ARPCACHE_H
