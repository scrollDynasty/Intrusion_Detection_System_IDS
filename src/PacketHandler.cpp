#include "PacketHandler.h"
#include <iostream>
#include <map>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

struct ip_hdr {
    unsigned char ip_hl : 4;
    unsigned char ip_v : 4;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct tcp_hdr {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_ptr;
};

void PacketHandler::logEvent(const std::string& message) {
    std::cout << "[" << time(nullptr) << "] " << message << std::endl;
}

void PacketHandler::processPacket(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* self = reinterpret_cast<PacketHandler*>(userData);
    auto* ipHeader = (struct ip_hdr*)(packet + 14);

    if (ipHeader->ip_p == IPPROTO_TCP) {
        auto* tcpHeader = (struct tcp_hdr*)(packet + 14 + (ipHeader->ip_hl * 4));

        if (tcpHeader->flags & 0x02) {
            char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

            self->logEvent("SYN packet detected!");
            std::cout << "Source: " << srcIP << " -> Purpose: " << dstIP << std::endl;
        }
    }
}

bool PacketHandler::startCapture(const std::string& deviceName) {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errorBuffer);

    if (handle == nullptr) {
        std::cerr << "Error: " << errorBuffer << std::endl;
        return false;
    }

    std::cout << "Let's start capturing packets..." << std::endl;

    pcap_loop(handle, 0, processPacket, reinterpret_cast<u_char*>(this));

    pcap_close(handle);
    return true;
}
