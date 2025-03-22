#ifndef PACKETHANDLER_H
#define PACKETHANDLER_H

#include <QObject>
#include <string>
#include <vector>
#include <pcap.h>

class PacketHandler : public QObject
{
    Q_OBJECT

public:
    explicit PacketHandler(QObject *parent = nullptr);
    ~PacketHandler();

    bool startCapture(const std::string& interface, QString* errorMessage = nullptr);
    void stopCapture();
    std::vector<std::string> getAvailableInterfaces();

signals:
    void packetDetected(const QString& source, const QString& destination, 
                       const QString& type, const QString& timestamp, bool isThreat);

private:
    pcap_t* handle;
    bool isRunning;
    int packetCount;
    std::vector<std::string> localIPAddresses;
    static PacketHandler* currentInstance;

    static void processPacket(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    std::vector<std::string> getLocalIPAddresses();
    void incrementPacketCount();
    void logEvent(const std::string& message);
};

#endif // PACKETHANDLER_H 