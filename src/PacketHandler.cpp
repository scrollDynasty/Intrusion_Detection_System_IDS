#include "PacketHandler.h"
#include <iostream>
#include <map>
#include <ctime>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <QDateTime>
#include <QMetaType>
#include <QThread>
#include <QDebug>
#include <functional>

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

PacketHandler::PacketHandler(QObject *parent)
    : QObject(parent), handle(nullptr), isRunning(false), packetCount(0) {
}

PacketHandler::~PacketHandler() {
    stopCapture();
}

void PacketHandler::logEvent(const std::string& message) {
    std::cout << "[" << time(nullptr) << "] " << message << std::endl;
}

void PacketHandler::processPacket(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    auto* self = reinterpret_cast<PacketHandler*>(userData);
    
    if (!self->isRunning) {
        return;
    }
    
    auto* ipHeader = (struct ip_hdr*)(packet + 14);

    if (ipHeader->ip_p == IPPROTO_TCP) {
        auto* tcpHeader = (struct tcp_hdr*)(packet + 14 + (ipHeader->ip_hl * 4));

        if (tcpHeader->flags & 0x02) { // SYN flag
            char srcIP[INET_ADDRSTRLEN], dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

            self->logEvent("SYN packet detected!");
            std::cout << "Source: " << srcIP << " -> Purpose: " << dstIP << std::endl;
            
            // Увеличиваем счетчик пакетов
            self->packetCount++;
            
            // Отправляем сигнал с информацией о пакете
            QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
            emit self->packetDetected(QString(srcIP), QString(dstIP), "SYN", timestamp);
        }
    }
}

bool PacketHandler::startCapture(const std::string& deviceName) {
    if (isRunning) {
        return false;
    }
    
    char errorBuffer[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errorBuffer);

    if (handle == nullptr) {
        std::cerr << "Error: " << errorBuffer << std::endl;
        return false;
    }

    isRunning = true;
    packetCount = 0;
    
    // Запускаем захват пакетов в отдельном потоке
    QThread* thread = new QThread();
    this->moveToThread(thread);
    
    connect(thread, &QThread::started, [this]() {
        std::cout << "Let's start capturing packets..." << std::endl;
        pcap_loop(handle, 0, processPacket, reinterpret_cast<u_char*>(this));
    });
    
    connect(thread, &QThread::finished, [this, thread]() {
        if (handle) {
            pcap_close(handle);
            handle = nullptr;
        }
        thread->deleteLater();
    });
    
    thread->start();
    
    return true;
}

void PacketHandler::stopCapture() {
    if (!isRunning) {
        return;
    }
    
    isRunning = false;
    
    if (handle) {
        pcap_breakloop(handle);
    }
    
    if (QThread::currentThread() != this->thread()) {
        this->thread()->quit();
        this->thread()->wait();
    }
}
