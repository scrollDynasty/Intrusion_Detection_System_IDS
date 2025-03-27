#ifndef SIMPLE_PACKET_HANDLER_H
#define SIMPLE_PACKET_HANDLER_H

#include <string>
#include <vector>
#include <thread>
#include <pcap.h>
#include <functional>
#include <set>
#include <unordered_map>
#include <netinet/ether.h>

/**
 * @brief Класс для захвата и анализа сетевых пакетов (версия без Qt)
 */
class SimplePacketHandler {
public:
    /**
     * @brief Тип функции обратного вызова для обработки обнаруженных пакетов
     */
    using PacketDetectedCallback = std::function<void(const std::string&, const std::string&, 
                                                    const std::string&, const std::string&, bool)>;
    
    /**
     * @brief Конструктор
     */
    SimplePacketHandler();
    
    /**
     * @brief Деструктор
     */
    ~SimplePacketHandler();
    
    /**
     * @brief Запуск захвата пакетов
     * @param deviceName Имя сетевого интерфейса
     * @param errorMessage Указатель на строку для сообщения об ошибке (может быть nullptr)
     * @return true в случае успешного запуска, false в противном случае
     */
    bool startCapture(const std::string& deviceName, std::string* errorMessage = nullptr);
    
    /**
     * @brief Остановка захвата пакетов
     */
    void stopCapture();
    
    /**
     * @brief Установка обработчика обнаружения пакета
     * @param callback Функция обратного вызова
     */
    void setPacketDetectedCallback(PacketDetectedCallback callback);
    
private:
    pcap_t* handle;                          // Дескриптор для захвата пакетов
    bool isRunning;                          // Флаг активного захвата
    std::thread captureThread;               // Поток захвата пакетов
    uint64_t packetCount;                    // Счетчик захваченных пакетов
    std::vector<std::string> localIPAddresses; // Список локальных IP-адресов
    PacketDetectedCallback onPacketDetectedCallback; // Обработчик обнаружения пакета
    
    /**
     * @brief Статический метод для обработки пакетов
     */
    static void packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    
    /**
     * @brief Обработка пакета
     */
    void processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet);
    
    /**
     * @brief Получение списка локальных IP-адресов
     */
    std::vector<std::string> getLocalIPAddresses();
    
    /**
     * @brief Логирование событий
     */
    void logEvent(const std::string& message);
    
    /**
     * @brief Конвертация MAC-адреса в строку
     */
    std::string macToString(const u_char* mac);
};

#endif // SIMPLE_PACKET_HANDLER_H 