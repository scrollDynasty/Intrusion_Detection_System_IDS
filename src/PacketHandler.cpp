#include "PacketHandler.h"
#include "ip_hdr.h"
#include "tcp_hdr.h"
#include <iostream>
#include <map>
#include <ctime>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif
#include <QDateTime>
#include <QMetaType>
#include <QThread>
#include <QDebug>
#include <functional>
#include <thread>
#include <unordered_map>
#include <chrono>
#include <QFile>

// Структуры ip_hdr и tcp_hdr переносятся в include/ip_hdr.h и include/tcp_hdr.h

// Структура для отслеживания частоты пакетов для обнаружения DOS-атак
struct PacketFrequencyTracker {
    std::unordered_map<std::string, int> packetCount; // IP -> количество пакетов
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lastReset; // IP -> время последнего сброса
    
    // Константы для обнаружения атак
    static constexpr int SYN_FLOOD_THRESHOLD = 100; // Порог для SYN-флуда
    static constexpr int UDP_FLOOD_THRESHOLD = 150; // Порог для UDP-флуда
    static constexpr int ICMP_FLOOD_THRESHOLD = 50; // Порог для ICMP-флуда
    static constexpr int INTERVAL_SECONDS = 60;     // Интервал для измерения (в секундах)
    
    // Увеличивает счетчик пакетов для заданного IP-адреса и проверяет порог
    bool incrementAndCheck(const std::string& ip, int threshold, const std::string& attackType) {
        auto now = std::chrono::steady_clock::now();
        
        // Если это первый пакет или истек интервал, сбросить счетчик
        if (lastReset.find(ip) == lastReset.end() || 
            std::chrono::duration_cast<std::chrono::seconds>(now - lastReset[ip]).count() > INTERVAL_SECONDS) {
            packetCount[ip] = 1;
            lastReset[ip] = now;
            return false;
        }
        
        // Увеличиваем счетчик
        packetCount[ip]++;
        
        // Проверяем, превышен ли порог
        if (packetCount[ip] > threshold) {
            qDebug() << "ALERT: Possible" << QString::fromStdString(attackType) << "attack detected from IP:" << QString::fromStdString(ip) 
                    << "(" << packetCount[ip] << "packets in" << INTERVAL_SECONDS << "seconds)";
            return true;
        }
        
        return false;
    }
};

// Структура для отслеживания попыток подключения для обнаружения брутфорс-атак
struct BruteForceTracker {
    std::unordered_map<std::string, std::unordered_map<int, int>> connectionAttempts; // IP -> (порт -> количество)
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lastReset; // IP -> время последнего сброса
    
    // Константы для обнаружения атак
    static constexpr int BRUTE_FORCE_THRESHOLD = 10; // Порог для брутфорса
    static constexpr int INTERVAL_SECONDS = 60;      // Интервал для измерения (в секундах)
    
    // Увеличивает счетчик попыток для заданного IP-адреса и порта, проверяет порог
    bool incrementAndCheck(const std::string& ip, int port) {
        auto now = std::chrono::steady_clock::now();
        
        // Если это первая попытка или истек интервал, сбросить счетчик
        if (lastReset.find(ip) == lastReset.end() || 
            std::chrono::duration_cast<std::chrono::seconds>(now - lastReset[ip]).count() > INTERVAL_SECONDS) {
            connectionAttempts[ip].clear();
            connectionAttempts[ip][port] = 1;
            lastReset[ip] = now;
            return false;
        }
        
        // Увеличиваем счетчик
        connectionAttempts[ip][port]++;
        
        // Проверяем, превышен ли порог
        if (connectionAttempts[ip][port] > BRUTE_FORCE_THRESHOLD) {
            qDebug() << "ALERT: Possible brute force attack detected from IP:" << QString::fromStdString(ip) 
                    << "to port" << port << "(" << connectionAttempts[ip][port] << "attempts in" << INTERVAL_SECONDS << "seconds)";
            return true;
        }
        
        return false;
    }
};

// Добавляем статические экземпляры трекеров
static PacketFrequencyTracker dosTracker;
static BruteForceTracker bruteForceTracker;

// Инициализация статического указателя
PacketHandler* PacketHandler::currentInstance = nullptr;

PacketHandler::PacketHandler(QObject *parent)
    : QObject(parent), handle(nullptr), isRunning(false), packetCount(0) {
    // Получаем локальные IP-адреса при инициализации
    localIPAddresses = getLocalIPAddresses();
    
    // Устанавливаем текущий экземпляр
    currentInstance = this;
    
    // Выводим все найденные локальные IP адреса
    qDebug() << "Локальные IP-адреса:";
    for (const auto& ip : localIPAddresses) {
        qDebug() << QString::fromStdString(ip);
    }
}

PacketHandler::~PacketHandler() {
    stopCapture();
    if (currentInstance == this) {
        currentInstance = nullptr;
    }
}

void PacketHandler::logEvent(const std::string& message) {
    std::cout << "[" << time(nullptr) << "] " << message << std::endl;
}

void PacketHandler::processPacket(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    try {
        // Используем статический указатель для доступа к текущему экземпляру
        PacketHandler *handler = currentInstance;
        if (!handler) {
            qDebug() << "Ошибка: нет активного экземпляра PacketHandler";
            return;
        }
        
        // Отладочный вывод
        qDebug() << "Получен пакет размером" << pkthdr->len << "байт";
        
        // Проверяем, что пакет достаточно большой для заголовка Ethernet
        if (pkthdr->len < 14) {
            qDebug() << "Пакет слишком маленький для заголовка Ethernet";
            return;
        }
        
        // Выводим MAC-адреса для отладки
        QString srcMac = QString("%1:%2:%3:%4:%5:%6")
                        .arg(packet[6], 2, 16, QChar('0'))
                        .arg(packet[7], 2, 16, QChar('0'))
                        .arg(packet[8], 2, 16, QChar('0'))
                        .arg(packet[9], 2, 16, QChar('0'))
                        .arg(packet[10], 2, 16, QChar('0'))
                        .arg(packet[11], 2, 16, QChar('0'));
        
        QString dstMac = QString("%1:%2:%3:%4:%5:%6")
                        .arg(packet[0], 2, 16, QChar('0'))
                        .arg(packet[1], 2, 16, QChar('0'))
                        .arg(packet[2], 2, 16, QChar('0'))
                        .arg(packet[3], 2, 16, QChar('0'))
                        .arg(packet[4], 2, 16, QChar('0'))
                        .arg(packet[5], 2, 16, QChar('0'));
        
        qDebug() << "MAC:" << srcMac << "->" << dstMac;
        
        // Получаем тип Ethernet пакета (смещение 12, длина 2 байта)
        u_short etherType = ((packet[12] << 8) | packet[13]);
        
        qDebug() << "EtherType:" << QString("0x%1").arg(etherType, 4, 16, QChar('0'));
        
        // Если это не IP пакет, просто увеличиваем счетчик и выходим
        if (etherType != 0x0800) {
            qDebug() << "Пакет не является IP пакетом, тип:" << etherType;
            
            // Увеличиваем счетчик пакетов
            handler->incrementPacketCount();
            
            // Для ARP пакетов (0x0806) можем добавить обработку
            if (etherType == 0x0806) {
                qDebug() << "Обнаружен ARP пакет";
                
                // Получаем текущее время
                QDateTime now = QDateTime::currentDateTime();
                QString timestamp = now.toString("yyyy-MM-dd hh:mm:ss");
                
                // Отправляем сигнал с информацией о пакете
                emit handler->packetDetected(srcMac, dstMac, "ARP пакет", timestamp, false);
            }
            
            return;
        }
        
        // Получаем IP заголовок (смещение 14 байт от начала пакета)
        const ids_ip_hdr *ipHeader = reinterpret_cast<const ids_ip_hdr*>(packet + 14);
        
        // Проверяем, что заголовок IP корректный
        if (pkthdr->len < 14 + 20) {
            qDebug() << "Пакет слишком маленький для заголовка IP";
            return;
        }
        
        // Получаем IP адреса
        char sourceIP[INET_ADDRSTRLEN];
        char destIP[INET_ADDRSTRLEN];
        
        // Безопасное копирование IP адресов
        if (inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN) == nullptr) {
            qDebug() << "Ошибка при преобразовании IP-адреса источника";
            strcpy(sourceIP, "unknown");
        }
        
        if (inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN) == nullptr) {
            qDebug() << "Ошибка при преобразовании IP-адреса назначения";
            strcpy(destIP, "unknown");
        }
        
        qDebug() << "IP пакет:" << sourceIP << "->" << destIP << "Протокол:" << (int)ipHeader->ip_p;
        
        // Выводим список локальных IP для отладки
        qDebug() << "Локальные IP-адреса:";
        for (const auto& ip : handler->localIPAddresses) {
            qDebug() << "  " << QString::fromStdString(ip);
        }
        
        // Проверяем, является ли IP-адрес источника или назначения локальным
        bool isSourceLocal = false;
        bool isDestLocal = false;
        
        for (const auto& localIP : handler->localIPAddresses) {
            if (localIP == sourceIP) {
                isSourceLocal = true;
                qDebug() << "IP источника" << sourceIP << "является локальным";
            }
            if (localIP == destIP) {
                isDestLocal = true;
                qDebug() << "IP назначения" << destIP << "является локальным";
            }
        }
        
        if (!isSourceLocal) {
            qDebug() << "IP источника" << sourceIP << "является внешним";
        }
        if (!isDestLocal) {
            qDebug() << "IP назначения" << destIP << "является внешним";
        }
        
        // Определяем тип пакета
        QString packetType;
        QString details;
        bool isPotentialThreat = false;
        
        // Получаем текущее время
        QDateTime now = QDateTime::currentDateTime();
        QString timestamp = now.toString("yyyy-MM-dd hh:mm:ss");
        
        // Обрабатываем разные типы пакетов
        switch (ipHeader->ip_p) {
            case IPPROTO_TCP: { // TCP
                // Размер IP заголовка (IP header length * 4 bytes)
                int ipHeaderSize = (ipHeader->ip_hl & 0x0F) * 4;
                
                // Получаем TCP заголовок
                const ids_tcp_hdr *tcpHeader = reinterpret_cast<const ids_tcp_hdr*>(
                    packet + 14 + ipHeaderSize);
                
                // Получаем порты
                int sourcePort = ntohs(tcpHeader->th_sport);
                int destPort = ntohs(tcpHeader->th_dport);
                
                qDebug() << "TCP пакет:" << sourceIP << ":" << sourcePort << "->" << destIP << ":" << destPort;
                qDebug() << "TCP флаги:" << QString("0x%1").arg(tcpHeader->th_flags, 2, 16, QChar('0'));
                
                // Проверяем известные сервисы на предмет возможных брутфорс-атак
                if ((destPort == 22 || destPort == 23 || destPort == 3389 || destPort == 5900 || 
                     destPort == 21 || destPort == 3306 || destPort == 1433) && 
                    (tcpHeader->th_flags & TH_SYN) && isDestLocal && !isSourceLocal) {
                    if (bruteForceTracker.incrementAndCheck(sourceIP, destPort)) {
                        details = " (Порт " + QString::number(sourcePort) + " → " + QString::number(destPort) + ") ВОЗМОЖНАЯ БРУТФОРС-АТАКА!";
                        isPotentialThreat = true;
                    }
                }
                
                // Проверяем на SYN-флуд (много SYN пакетов)
                if ((tcpHeader->th_flags & TH_SYN) && !(tcpHeader->th_flags & TH_ACK) && isDestLocal) {
                    if (dosTracker.incrementAndCheck(sourceIP, dosTracker.SYN_FLOOD_THRESHOLD, "SYN flood")) {
                        details += " (ВОЗМОЖНАЯ SYN-ФЛУД АТАКА!)";
                        isPotentialThreat = true;
                    }
                }
                
                // Проверяем, является ли это сканированием портов с другого компьютера
                // Если источник не локальный, а назначение локальное, и это SYN пакет - вероятно, это сканирование
                if (!isSourceLocal && isDestLocal && (tcpHeader->th_flags & TH_SYN) && !(tcpHeader->th_flags & TH_ACK)) {
                    qDebug() << "ВНИМАНИЕ: Обнаружено возможное сканирование портов с внешнего IP:" << sourceIP;
                    qDebug() << "  Порт назначения:" << destPort;
                    
                    packetType = "TCP SYN";
                    details = " (Порт " + QString::number(sourcePort) + " → " + QString::number(destPort) + ") Возможное сканирование портов с внешнего IP";
                    isPotentialThreat = true;
                    
                    // Увеличиваем счетчик пакетов
                    handler->incrementPacketCount();
                    
                    // Отправляем сигнал с информацией о пакете
                    qDebug() << "Отправляем сигнал packetDetected:" << QString(sourceIP) << QString(destIP) << packetType + details << timestamp;
                    emit handler->packetDetected(QString(sourceIP), QString(destIP), packetType + details, timestamp, isPotentialThreat);
                    
                    return;
                }
                
                // Определяем флаги TCP
                if (tcpHeader->th_flags & TH_SYN) { // SYN
                    if (tcpHeader->th_flags & TH_ACK) { // ACK
                        packetType = "TCP SYN-ACK";
                    } else {
                        packetType = "TCP SYN";
                        
                        // Проверяем на возможное сканирование портов
                        // Сканирование портов обычно направлено на привилегированные порты (< 1024)
                        // Теперь проверяем как внешние, так и внутренние сканирования
                        if (destPort < 1024 && isDestLocal && !isSourceLocal) {
                            details = " (Порт " + QString::number(sourcePort) + " → " + QString::number(destPort) + ") Возможное сканирование портов с внешнего IP";
                            isPotentialThreat = true;
                            
                            // Выводим подробную информацию о сканировании портов
                            qDebug() << "ОБНАРУЖЕНО СКАНИРОВАНИЕ ПОРТОВ:";
                            qDebug() << "  Внешний IP:" << sourceIP;
                            qDebug() << "  Локальный IP:" << destIP;
                            qDebug() << "  Порт источника:" << sourcePort;
                            qDebug() << "  Порт назначения:" << destPort;
                            qDebug() << "  TCP флаги:" << QString("0x%1").arg(tcpHeader->th_flags, 2, 16, QChar('0'));
                        } else if (destPort < 1024) {
                            details = " (Порт " + QString::number(sourcePort) + " → " + QString::number(destPort) + ") Возможное сканирование портов";
                            isPotentialThreat = true;
                        } else {
                            details = " (Порт " + QString::number(sourcePort) + " -> " + QString::number(destPort) + ")";
                        }
                    }
                } else if (tcpHeader->th_flags & TH_FIN) { // FIN
                    packetType = "TCP FIN";
                    details = " (Порт " + QString::number(sourcePort) + " -> " + QString::number(destPort) + ") Завершение соединения";
                } else if (tcpHeader->th_flags & TH_RST) { // RST
                    packetType = "TCP RST";
                    details = " (Порт " + QString::number(sourcePort) + " -> " + QString::number(destPort) + ") Сброс соединения";
                    
                    // Множественные RST пакеты могут указывать на попытки сброса соединений
                    // Здесь можно добавить логику для отслеживания частоты RST пакетов
                } else if (tcpHeader->th_flags & TH_ACK) { // ACK
                    packetType = "TCP ACK";
                    details = " (Порт " + QString::number(sourcePort) + " -> " + QString::number(destPort) + ") Подтверждение";
                } else {
                    packetType = "TCP";
                    details = " (Порт " + QString::number(sourcePort) + " -> " + QString::number(destPort) + ")";
                }
                
                // Проверка на известные вредоносные порты
                if (destPort == 445 || destPort == 135 || destPort == 139 || // SMB/NetBIOS
                    destPort == 3389 || // RDP
                    destPort == 22 || // SSH
                    destPort == 23 || // Telnet
                    destPort == 1433 || destPort == 1434 || // MS SQL
                    destPort == 3306) { // MySQL
                    
                    // Если это попытка подключения (SYN) к известному порту
                    if (tcpHeader->th_flags & TH_SYN && !(tcpHeader->th_flags & TH_ACK)) {
                        if (!isSourceLocal && isDestLocal) {
                            details += " (Попытка подключения к потенциально уязвимому сервису с внешнего IP)";
                        } else {
                            details += " (Попытка подключения к потенциально уязвимому сервису)";
                        }
                        isPotentialThreat = true;
                    }
                }
                
                break;
            }
            case IPPROTO_UDP: { // UDP
                // Проверяем, что пакет достаточно большой для UDP заголовка
                if (pkthdr->len < 14 + (ipHeader->ip_hl * 4) + 8) {
                    qDebug() << "Пакет слишком маленький для заголовка UDP";
                    return;
                }
                
                // Получаем UDP заголовок (8 байт)
                const u_char *udpHeader = packet + 14 + (ipHeader->ip_hl * 4);
                
                // Получаем порты (первые 2 байта - порт источника, следующие 2 - порт назначения)
                int sourcePort = (udpHeader[0] << 8) | udpHeader[1];
                int destPort = (udpHeader[2] << 8) | udpHeader[3];
                
                qDebug() << "UDP пакет:" << sourceIP << ":" << sourcePort << "->" << destIP << ":" << destPort;
                
                packetType = "UDP";
                details = " (Порт " + QString::number(sourcePort) + " -> " + QString::number(destPort) + ")";
                
                // Проверка на UDP-флуд атаки
                if (isDestLocal) {
                    if (dosTracker.incrementAndCheck(sourceIP, dosTracker.UDP_FLOOD_THRESHOLD, "UDP flood")) {
                        details += " (ВОЗМОЖНАЯ UDP-ФЛУД АТАКА!)";
                        isPotentialThreat = true;
                    }
                }
                
                // Проверка на известные уязвимые UDP порты
                if (destPort == 53 || // DNS
                    destPort == 161 || destPort == 162 || // SNMP
                    destPort == 1900 || // UPnP
                    destPort == 5353) { // mDNS
                    
                    // Если пакет направлен на локальный компьютер с внешнего IP
                    if (!isSourceLocal && isDestLocal) {
                        details += " (Возможный UDP флуд с внешнего IP)";
                        isPotentialThreat = true;
                    }
                    // Здесь можно добавить логику для отслеживания частоты UDP пакетов
                    // на эти порты для обнаружения UDP флуда
                }
                
                break;
            }
            case IPPROTO_ICMP: { // ICMP
                qDebug() << "ICMP пакет:" << sourceIP << "->" << destIP;
                
                packetType = "ICMP";
                
                // Проверка на ICMP-флуд атаки
                if (isDestLocal) {
                    if (dosTracker.incrementAndCheck(sourceIP, dosTracker.ICMP_FLOOD_THRESHOLD, "ICMP flood")) {
                        details += " (ВОЗМОЖНАЯ PING-ФЛУД АТАКА!)";
                        isPotentialThreat = true;
                    }
                }
                
                // Если пакет направлен на локальный компьютер с внешнего IP
                if (!isSourceLocal && isDestLocal) {
                    details = " (ping с внешнего IP)";
                    
                    // С некоторой вероятностью помечаем как потенциальную угрозу
                    // Здесь можно добавить логику для отслеживания частоты ICMP пакетов
                    // для обнаружения ping flood
                } else {
                    details = " (ping)";
                }
                
                break;
            }
            default: {
                qDebug() << "Неизвестный протокол:" << (int)ipHeader->ip_p;
                
                packetType = "Другой";
                details = " (Протокол " + QString::number(ipHeader->ip_p) + ")";
                
                break;
            }
        }
        
        // Увеличиваем счетчик пакетов через текущий экземпляр
        handler->incrementPacketCount();
        
        // Отправляем сигнал с информацией о пакете
        qDebug() << "Отправляем сигнал packetDetected:" << QString(sourceIP) << QString(destIP) << packetType + details << timestamp;
        emit handler->packetDetected(QString(sourceIP), QString(destIP), packetType + details, timestamp, isPotentialThreat);
    }
    catch (const std::exception& e) {
        qDebug() << "Ошибка при обработке пакета:" << e.what();
    }
}

std::vector<std::string> PacketHandler::getLocalIPAddresses() {
    std::vector<std::string> addresses;
    
#ifdef _WIN32
    // Windows-специфичный код для получения локальных IP-адресов
    ULONG outBufLen = 0;
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    
    // Сначала определяем размер буфера
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &outBufLen);
    
    // Выделяем память для буфера
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (pAddresses == nullptr) {
        qDebug() << "Ошибка при выделении памяти для IP_ADAPTER_ADDRESSES";
        return addresses;
    }
    
    // Получаем информацию об адаптерах
    DWORD result = GetAdaptersAddresses(AF_INET, 0, nullptr, pAddresses, &outBufLen);
    if (result != NO_ERROR) {
        qDebug() << "Ошибка GetAdaptersAddresses:" << result;
        free(pAddresses);
        return addresses;
    }
    
    // Перебираем все адаптеры
    for (PIP_ADAPTER_ADDRESSES adapter = pAddresses; adapter != nullptr; adapter = adapter->Next) {
        // Пропускаем отключенные адаптеры
        if (adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        
        // Перебираем все адреса для этого адаптера
        for (PIP_ADAPTER_UNICAST_ADDRESS address = adapter->FirstUnicastAddress; 
             address != nullptr; 
             address = address->Next) {
            
            // Обрабатываем только IPv4 адреса
            if (address->Address.lpSockaddr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(address->Address.lpSockaddr);
                
                // Преобразуем IP-адрес в строку
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
                addresses.push_back(ip);
                
                qDebug() << "Найден локальный IP-адрес:" << ip;
            }
        }
    }
    
    // Освобождаем память
    free(pAddresses);
#else
    // Linux-специфичный код для получения локальных IP-адресов
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char ip[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        qDebug() << "Ошибка getifaddrs";
        return addresses;
    }

    // Перебираем все сетевые интерфейсы
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;

        // Обрабатываем только IPv4 адреса
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            ip, INET_ADDRSTRLEN,
                            nullptr, 0, NI_NUMERICHOST);
            if (s != 0) {
                qDebug() << "Ошибка getnameinfo:" << gai_strerror(s);
                continue;
            }

            // Пропускаем локальный интерфейс 127.0.0.1
            if (strcmp(ip, "127.0.0.1") != 0) {
                addresses.push_back(ip);
                qDebug() << "Найден локальный IP-адрес:" << ip;
            }
        }
    }

    freeifaddrs(ifaddr);
#endif

    // Добавляем localhost
    addresses.push_back("127.0.0.1");
    
    return addresses;
}

bool PacketHandler::startCapture(const std::string& deviceName, QString* errorMessage) {
    try {
        if (isRunning) {
            if (errorMessage) {
                *errorMessage = "Захват пакетов уже запущен";
            }
            return false;
        }
        
        // Получаем локальные IP-адреса
        localIPAddresses = getLocalIPAddresses();
        
        // Выводим список локальных IP для отладки
        qDebug() << "Локальные IP-адреса:";
        for (const auto& ip : localIPAddresses) {
            qDebug() << "  " << QString::fromStdString(ip);
        }
        
        char errorBuffer[PCAP_ERRBUF_SIZE];
        
        // Проверяем, существует ли устройство
        pcap_if_t* allDevices;
        if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
            if (errorMessage) {
                *errorMessage = QString("Ошибка при поиске устройств: %1").arg(errorBuffer);
            }
            return false;
        }
        
        bool deviceFound = false;
        for (pcap_if_t* device = allDevices; device != nullptr; device = device->next) {
            qDebug() << "Доступное устройство:" << device->name << (device->description ? device->description : "");
            if (deviceName == device->name) {
                deviceFound = true;
                break;
            }
        }
        
        pcap_freealldevs(allDevices);
        
        if (!deviceFound) {
            if (errorMessage) {
                *errorMessage = QString("Устройство '%1' не найдено").arg(deviceName.c_str());
            }
            return false;
        }
        
        qDebug() << "Открываем устройство:" << QString::fromStdString(deviceName);
        
        // Открываем устройство для захвата пакетов в режиме promiscuous
        // Устанавливаем режим promiscuous (1), чтобы захватывать все пакеты в сети
        // Увеличиваем таймаут до 1000 мс для лучшего захвата пакетов
        handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errorBuffer);

        if (handle == nullptr) {
            if (errorMessage) {
                *errorMessage = QString("Ошибка при открытии устройства: %1").arg(errorBuffer);
            }
            std::cerr << "Error: " << errorBuffer << std::endl;
            return false;
        }
        
        // Проверяем, что устройство поддерживает режим promiscuous
        // Для этого пробуем получить статистику
        struct pcap_stat stats;
        if (pcap_stats(handle, &stats) != 0) {
            qDebug() << "Предупреждение: не удалось получить статистику устройства. Возможно, режим promiscuous не поддерживается.";
        } else {
            qDebug() << "Статистика устройства: получено пакетов:" << stats.ps_recv 
                     << ", отброшено:" << stats.ps_drop 
                     << ", отброшено интерфейсом:" << stats.ps_ifdrop;
        }
        
        // Проверяем тип канального уровня
        int linkType = pcap_datalink(handle);
        qDebug() << "Тип канального уровня:" << linkType;
        
        // Если это не Ethernet, выводим предупреждение
        if (linkType != DLT_EN10MB) {
            qDebug() << "Предупреждение: устройство не использует Ethernet. Захват может работать некорректно.";
        }
        
        // Устанавливаем фильтр для захвата всех пакетов в сети
        struct bpf_program fp;
        // Пустой фильтр для захвата всех пакетов
        const char* filter = "";
        
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            if (errorMessage) {
                *errorMessage = QString("Ошибка при компиляции фильтра: %1").arg(pcap_geterr(handle));
            }
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            if (errorMessage) {
                *errorMessage = QString("Ошибка при установке фильтра: %1").arg(pcap_geterr(handle));
            }
            pcap_freecode(&fp);
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        
        pcap_freecode(&fp);
        
        // Проверяем, включен ли режим promiscuous
        int status = pcap_setnonblock(handle, 1, errorBuffer);
        if (status != 0) {
            qDebug() << "Предупреждение: не удалось установить неблокирующий режим:" << errorBuffer;
        }
        
        qDebug() << "Режим promiscuous активирован. Захват всех пакетов в сети.";
        
        // Выводим предупреждение о том, что для работы в режиме promiscuous нужны права администратора
        qDebug() << "ВАЖНО: Для работы в режиме promiscuous необходимо запустить программу от имени администратора.";
        qDebug() << "       Также убедитесь, что выбранный сетевой адаптер поддерживает режим promiscuous.";

        isRunning = true;
        packetCount = 0;
        
        qDebug() << "Запускаем захват пакетов...";
        
        // Запускаем захват пакетов в отдельном потоке без перемещения объекта
        std::thread captureThread([this]() {
            try {
                std::cout << "Let's start capturing packets..." << std::endl;
                pcap_loop(handle, 0, processPacket, reinterpret_cast<u_char*>(this));
            }
            catch (const std::exception& e) {
                qCritical() << "Исключение в потоке захвата:" << e.what();
            }
            catch (...) {
                qCritical() << "Неизвестное исключение в потоке захвата";
            }
            
            // После завершения захвата
            if (handle) {
                pcap_close(handle);
                handle = nullptr;
            }
        });
        
        // Отсоединяем поток, чтобы он работал независимо
        captureThread.detach();
        
        return true;
    }
    catch (const std::exception& e) {
        if (errorMessage) {
            *errorMessage = QString("Исключение при запуске захвата: %1").arg(e.what());
        }
        qCritical() << "Исключение в startCapture:" << e.what();
        return false;
    }
    catch (...) {
        if (errorMessage) {
            *errorMessage = "Неизвестное исключение при запуске захвата";
        }
        qCritical() << "Неизвестное исключение в startCapture";
        return false;
    }
}

void PacketHandler::stopCapture() {
    try {
        if (!isRunning) {
            return;
        }
        
        isRunning = false;
        
        if (handle) {
            pcap_breakloop(handle);
        }
    }
    catch (const std::exception& e) {
        qCritical() << "Исключение в stopCapture:" << e.what();
    }
    catch (...) {
        qCritical() << "Неизвестное исключение в stopCapture";
    }
}

std::vector<std::string> PacketHandler::getAvailableInterfaces() {
    std::vector<std::string> interfaces;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "Ошибка при поиске устройств:" << errbuf;
        return interfaces;
    }
    
    for (pcap_if_t *d = alldevs; d; d = d->next) {
        // Добавляем все интерфейсы, кроме loopback
        if (strcmp(d->name, "lo") != 0) {
            interfaces.push_back(d->name);
            qDebug() << "Найден интерфейс:" << d->name << (d->description ? d->description : "");
        }
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

void PacketHandler::incrementPacketCount() {
    packetCount++;
    if (packetCount % 100 == 0) {
        qDebug() << "Обработано пакетов:" << packetCount;
    }
}
