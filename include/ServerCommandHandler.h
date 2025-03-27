#ifndef SERVER_COMMAND_HANDLER_H
#define SERVER_COMMAND_HANDLER_H

#include <string>
#include <thread>
#include <unordered_map>

// Предварительное объявление классов для уменьшения зависимостей
class SimplePacketHandler;
class DeviceManagerConsole;
class ServerSuspiciousIPModel;

/**
 * @brief Класс для управления IDS системой в консольном режиме (без GUI)
 * 
 * ServerCommandHandler обрабатывает консольные команды для управления 
 * системой обнаружения вторжений в режиме SSH-сервера.
 */
class ServerCommandHandler {
    
public:
    /**
     * @brief Конструктор по умолчанию
     */
    ServerCommandHandler();
    
    /**
     * @brief Деструктор
     */
    ~ServerCommandHandler();
    
    /**
     * @brief Запуск захвата пакетов на указанном интерфейсе
     * @param deviceIndex Индекс устройства из списка
     * @return true в случае успешного запуска, false в противном случае
     */
    bool startCapture(int deviceIndex);
    
    /**
     * @brief Остановка захвата пакетов
     */
    void stopCapture();
    
    /**
     * @brief Запуск интерактивного режима командной строки
     */
    void runInteractive();
    
    /**
     * @brief Обработка команды
     * @param commandLine Строка с командой
     */
    void processCommand(const std::string& commandLine);
    
    /**
     * @brief Установка режима подробного вывода
     * @param mode true для включения, false для отключения
     */
    void setVerboseMode(bool mode);
    
    /**
     * @brief Установка пароля для шифрования логов
     * @param password Пароль для шифрования
     */
    void setEncryptionPassword(const std::string& password);
    
    /**
     * @brief Подключение к сигналу обнаружения пакета
     * @param handler Функция обратного вызова
     */
    template<typename F>
    void connect(SimplePacketHandler* source, F handler) {
        // Пустая реализация для совместимости
    }
    
    /**
     * @brief Обработчик обнаруженного пакета
     * @param srcMAC MAC-адрес источника
     * @param dstMAC MAC-адрес назначения
     * @param packetInfo Информация о пакете
     * @param timestamp Временная метка
     * @param isPotentialThreat Флаг потенциальной угрозы
     */
    void onPacketDetected(const std::string& srcMAC, const std::string& dstMAC,
                         const std::string& packetInfo, const std::string& timestamp,
                         bool isPotentialThreat);
    
    /**
     * @brief Сохранение лога в файл
     * @param fileName Имя файла для сохранения
     * @return true в случае успешного сохранения, false в противном случае
     */
    bool saveLogsToFile(const std::string& fileName);
    
    /**
     * @brief Расшифровка лога из файла и вывод на экран
     * @param fileName Имя файла для расшифровки
     * @return true в случае успешной расшифровки, false в противном случае
     */
    bool decryptLogsFromFile(const std::string& fileName);
    
private:
    // Объекты для работы с пакетами и устройствами
    SimplePacketHandler* m_packetHandler;
    DeviceManagerConsole* m_deviceManager;
    ServerSuspiciousIPModel* m_suspiciousIPModel;
    
    // Флаги состояния
    bool m_isCapturing;      // Флаг активного захвата пакетов
    bool m_verboseMode;      // Режим подробного вывода
    bool m_encryptionEnabled; // Режим шифрования логов
    
    // Статистика
    int m_totalPacketsDetected;  // Всего обработано пакетов
    int m_totalAlertsDetected;   // Всего обнаружено угроз
    
    // Хранение информации о последнем выбранном устройстве
    int m_lastDeviceIndex;
    
    // Поток для тестового режима
    std::thread m_captureThread;
    
    // Поток для автоматического сохранения логов
    std::thread m_autoSaveTimer;
    
    // Счетчик для автоматического сохранения логов
    int m_autoSaveCounter;
    
    // Список подозрительных IP-адресов и время последней активности
    std::unordered_map<std::string, std::string> m_suspiciousIPs;
    
    // Пароль для шифрования логов
    std::string m_encryptionPassword;
    
    /**
     * @brief Генерация тестового трафика
     */
    void generateTestTraffic();
    
    /**
     * @brief Вывод списка доступных команд
     */
    void printHelp();
    
    /**
     * @brief Вывод статистики
     */
    void printStatistics();
    
    /**
     * @brief Вывод списка подозрительных IP-адресов
     */
    void printSuspiciousIPs();
    
    /**
     * @brief Вывод списка доступных сетевых интерфейсов
     */
    void printDeviceList();
};

#endif // SERVER_COMMAND_HANDLER_H 