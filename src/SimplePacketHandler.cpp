#include "SimplePacketHandler.h"
#include <iostream>
#include <ctime>
#include <chrono>
#include <thread>
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
#include <functional>
#include <algorithm>
#include <mutex>
#include <fstream>

// Глобальный мьютекс для синхронизации доступа к логам
std::mutex g_logMutex;

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
            std::cout << "ALERT: Possible" << attackType << "attack detected from IP:" << ip 
                    << "(" << packetCount[ip] << "packets in" << INTERVAL_SECONDS << "seconds)" << std::endl;
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
            std::cout << "ALERT: Possible brute force attack detected from IP:" << ip 
                    << "to port" << port << "(" << connectionAttempts[ip][port] << "attempts in" << INTERVAL_SECONDS << "seconds)" << std::endl;
            return true;
        }
        
        return false;
    }
};

// Создаем глобальные трекеры
static PacketFrequencyTracker dosTracker;
static BruteForceTracker bruteForceTracker;

// Конструктор
SimplePacketHandler::SimplePacketHandler() : handle(nullptr), isRunning(false), packetCount(0) {
    // Получаем локальные IP-адреса при инициализации
    localIPAddresses = getLocalIPAddresses();
    
    // Выводим все найденные локальные IP адреса
    std::cout << "Локальные IP-адреса:" << std::endl;
    for (const auto& ip : localIPAddresses) {
        std::cout << ip << std::endl;
    }
}

// Деструктор
SimplePacketHandler::~SimplePacketHandler() {
    stopCapture();
}

// Логирование событий
void SimplePacketHandler::logEvent(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::cout << "[" << time(nullptr) << "] " << message << std::endl;
}

// Получение списка локальных IP-адресов
std::vector<std::string> SimplePacketHandler::getLocalIPAddresses() {
    std::vector<std::string> addresses;
    
#ifdef _WIN32
    // Windows-специфичный код для получения IP-адресов
    ULONG bufLen = 15000;
    IP_ADAPTER_ADDRESSES* pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufLen);
    
    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(bufLen);
    }
    
    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &bufLen) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* adapter = pAddresses; adapter; adapter = adapter->Next) {
            for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast; unicast = unicast->Next) {
                if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* sa_in = (sockaddr_in*)unicast->Address.lpSockaddr;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ip, INET_ADDRSTRLEN);
                    addresses.push_back(ip);
                }
            }
        }
    }
    
    free(pAddresses);
#else
    // Linux-специфичный код для получения IP-адресов
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];
    
    if (getifaddrs(&ifaddr) == -1) {
        logEvent("Ошибка при вызове getifaddrs()");
        return addresses;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        
        family = ifa->ifa_addr->sa_family;
        
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                         host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                logEvent("Ошибка при вызове getnameinfo()");
                continue;
            }
            
            addresses.push_back(host);
        }
    }
    
    freeifaddrs(ifaddr);
#endif
    
    return addresses;
}

// Запуск захвата пакетов
bool SimplePacketHandler::startCapture(const std::string& deviceName, std::string* errorMessage) {
    if (isRunning) {
        if (errorMessage) *errorMessage = "Захват пакетов уже запущен";
        return false;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Открываем устройство для захвата
    handle = pcap_open_live(deviceName.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        if (errorMessage) *errorMessage = "Не удалось открыть устройство " + deviceName + ": " + errbuf;
        return false;
    }
    
    // Устанавливаем фильтр только для IP-пакетов
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        if (errorMessage) *errorMessage = "Не удалось скомпилировать фильтр: " + std::string(pcap_geterr(handle));
        pcap_close(handle);
        handle = NULL;
        return false;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        if (errorMessage) *errorMessage = "Не удалось установить фильтр: " + std::string(pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        handle = NULL;
        return false;
    }
    
    pcap_freecode(&fp);
    
    // Запускаем захват в отдельном потоке
    isRunning = true;
    captureThread = std::thread([this]() {
        // Захватываем пакеты
        pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(this));
    });
    
    return true;
}

// Остановка захвата пакетов
void SimplePacketHandler::stopCapture() {
    if (!isRunning) {
        return;
    }
    
    isRunning = false;
    
    // Останавливаем захват
    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = NULL;
    }
    
    // Ждем завершения потока
    if (captureThread.joinable()) {
        captureThread.join();
    }
}

// Статический метод для обработки пакетов
void SimplePacketHandler::packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    SimplePacketHandler *handler = reinterpret_cast<SimplePacketHandler*>(userData);
    handler->processPacket(pkthdr, packet);
}

// Обработка пакета
void SimplePacketHandler::processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    try {
        // Увеличиваем счетчик пакетов
        packetCount++;
        
        // Анализируем Ethernet-заголовок
        const struct ether_header *ethHeader = (const struct ether_header*)packet;
        
        // Получаем MAC-адреса
        std::string srcMac = macToString(ethHeader->ether_shost);
        std::string dstMac = macToString(ethHeader->ether_dhost);
        
        // Проверяем, что это IP-пакет (EtherType 0x0800)
        if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP) {
            // Не IP-пакет, пропускаем
            return;
        }
        
        // Анализируем IP-заголовок
        const struct ip *ipHeader = (const struct ip*)(packet + sizeof(struct ether_header));
        
        // Получаем IP-адреса
        char srcIP[INET_ADDRSTRLEN];
        char dstIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);
        
        std::string srcIPStr = srcIP;
        std::string dstIPStr = dstIP;
        
        // Проверяем, является ли это локальным адресом
        bool isOutgoing = std::find(localIPAddresses.begin(), localIPAddresses.end(), srcIPStr) != localIPAddresses.end();
        bool isIncoming = std::find(localIPAddresses.begin(), localIPAddresses.end(), dstIPStr) != localIPAddresses.end();
        
        // Определяем протокол
        int protocol = ipHeader->ip_p;
        std::string protocolStr;
        bool isPotentialThreat = false;
        std::string packetInfo;
        
        // Текущее время
        auto now = std::chrono::system_clock::now();
        std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
        char timeBuffer[80];
        std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", std::localtime(&timestamp));
        std::string timestampStr = timeBuffer;
        
        switch (protocol) {
            case IPPROTO_TCP: {
                protocolStr = "TCP";
                // Анализируем TCP-заголовок
                const struct tcphdr *tcpHeader = (const struct tcphdr*)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
                int srcPort = ntohs(tcpHeader->th_sport);
                int dstPort = ntohs(tcpHeader->th_dport);
                
                // Формирование информации о пакете
                packetInfo = "TCP пакет от " + srcIPStr + ":" + std::to_string(srcPort) + 
                             " к " + dstIPStr + ":" + std::to_string(dstPort);
                
                // Проверка SYN-флуда
                if (tcpHeader->th_flags & TH_SYN && !(tcpHeader->th_flags & TH_ACK)) {
                    if (isIncoming && dosTracker.incrementAndCheck(srcIPStr, PacketFrequencyTracker::SYN_FLOOD_THRESHOLD, "SYN-flood")) {
                        isPotentialThreat = true;
                        packetInfo = "Обнаружена SYN-флуд атака с IP: " + srcIPStr + " на порт " + std::to_string(dstPort);
                    }
                }
                
                // Проверка сканирования портов
                static std::unordered_map<std::string, std::set<int>> portScans;
                static std::unordered_map<std::string, std::chrono::steady_clock::time_point> scanTimers;
                
                if (isIncoming && (tcpHeader->th_flags & TH_SYN)) {
                    auto currentTime = std::chrono::steady_clock::now();
                    
                    // Если прошло более 5 минут с последнего обновления, сбрасываем счетчик
                    if (scanTimers.find(srcIPStr) == scanTimers.end() || 
                        std::chrono::duration_cast<std::chrono::minutes>(currentTime - scanTimers[srcIPStr]).count() > 5) {
                        portScans[srcIPStr].clear();
                    }
                    
                    // Добавляем порт в список
                    portScans[srcIPStr].insert(dstPort);
                    scanTimers[srcIPStr] = currentTime;
                    
                    // Если количество уникальных портов превышает порог, считаем это сканированием
                    if (portScans[srcIPStr].size() > 10) {
                        isPotentialThreat = true;
                        packetInfo = "Обнаружена попытка сканирования портов с IP: " + srcIPStr + 
                                    " (проверено " + std::to_string(portScans[srcIPStr].size()) + " портов)";
                        
                        // Сбрасываем счетчик
                        portScans[srcIPStr].clear();
                    }
                }
                
                // Проверка брутфорс-атак на определенные порты
                if (isIncoming && (dstPort == 22 || dstPort == 23 || dstPort == 3389)) {
                    if (bruteForceTracker.incrementAndCheck(srcIPStr, dstPort)) {
                        isPotentialThreat = true;
                        std::string serviceType;
                        if (dstPort == 22) serviceType = "SSH";
                        else if (dstPort == 23) serviceType = "Telnet";
                        else if (dstPort == 3389) serviceType = "RDP";
                        
                        packetInfo = "Обнаружена попытка брутфорс-атаки с IP: " + srcIPStr + " на " + serviceType + "-порт";
                    }
                }
                break;
            }
            case IPPROTO_UDP: {
                protocolStr = "UDP";
                // Анализируем UDP-заголовок
                const struct udphdr *udpHeader = (const struct udphdr*)(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
                int srcPort = ntohs(udpHeader->uh_sport);
                int dstPort = ntohs(udpHeader->uh_dport);
                
                // Формирование информации о пакете
                packetInfo = "UDP пакет от " + srcIPStr + ":" + std::to_string(srcPort) + 
                             " к " + dstIPStr + ":" + std::to_string(dstPort);
                
                // Проверка UDP флуда
                if (isIncoming && dosTracker.incrementAndCheck(srcIPStr, PacketFrequencyTracker::UDP_FLOOD_THRESHOLD, "UDP-flood")) {
                    isPotentialThreat = true;
                    packetInfo = "Обнаружена UDP-флуд атака с IP: " + srcIPStr;
                }
                break;
            }
            case IPPROTO_ICMP: {
                protocolStr = "ICMP";
                
                // Формирование информации о пакете
                packetInfo = "ICMP пакет от " + srcIPStr + " к " + dstIPStr;
                
                // Проверка ICMP флуда
                if (isIncoming && dosTracker.incrementAndCheck(srcIPStr, PacketFrequencyTracker::ICMP_FLOOD_THRESHOLD, "ICMP-flood")) {
                    isPotentialThreat = true;
                    packetInfo = "Обнаружена ICMP-флуд атака (ping-флуд) с IP: " + srcIPStr;
                }
                break;
            }
            default:
                protocolStr = "Unknown (" + std::to_string(protocol) + ")";
                packetInfo = protocolStr + " пакет от " + srcIPStr + " к " + dstIPStr;
                break;
        }
        
        // Вызываем обработчик события
        if (onPacketDetectedCallback) {
            onPacketDetectedCallback(srcMac, dstMac, packetInfo, timestampStr, isPotentialThreat);
        }
        
    } catch (const std::exception& e) {
        logEvent("Ошибка при обработке пакета: " + std::string(e.what()));
    } catch (...) {
        logEvent("Неизвестная ошибка при обработке пакета");
    }
}

// Конвертация MAC-адреса в строку
std::string SimplePacketHandler::macToString(const u_char* mac) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(macStr);
}

// Установка обработчика обнаружения пакета
void SimplePacketHandler::setPacketDetectedCallback(PacketDetectedCallback callback) {
    onPacketDetectedCallback = callback;
} 