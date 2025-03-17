#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <string>
#include <pcap.h>
#include <QObject>
#include <QString>
#include <QThread>
#include <atomic>
#include <vector>

class PacketHandler : public QObject {
    Q_OBJECT

public:
    explicit PacketHandler(QObject *parent = nullptr);
    ~PacketHandler();

    bool startCapture(const std::string& deviceName, QString* errorMessage = nullptr);
    void stopCapture();
    int getPacketCount() const { return packetCount; }
    
    void incrementPacketCount() { packetCount++; }

signals:
    void packetDetected(const QString& sourceIP, const QString& destinationIP, 
                       const QString& packetType, const QString& timestamp,
                       bool isPotentialThreat = false);

private:
    static void processPacket(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void logEvent(const std::string& message);
    std::vector<std::string> getLocalIPAddresses();
    
    pcap_t* handle;
    std::atomic<bool> isRunning;
    std::atomic<int> packetCount;
    QThread captureThread;
    std::vector<std::string> localIPAddresses;
};

#endif // PACKET_HANDLER_H
