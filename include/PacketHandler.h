#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <string>
#include <pcap.h>

class PacketHandler {
public:
    bool startCapture(const std::string& deviceName);

private:
    static void processPacket(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void logEvent(const std::string& message);
};

#endif // PACKET_HANDLER_H
