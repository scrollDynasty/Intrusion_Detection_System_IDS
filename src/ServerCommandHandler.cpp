#include "ServerCommandHandler.h"
#include "SimplePacketHandler.h"
#include "DeviceManagerConsole.h"
#include "ServerSuspiciousIPModel.h"
#include "ConsoleLogEncryption.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <fstream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <signal.h>
#include <unordered_map>
#include <vector>
#include <queue>
#include <algorithm>
#include <cctype>
#include <cstring>

// Глобальные переменные для обработки сигналов
bool g_running = true;
std::mutex g_mutex;
std::condition_variable g_cv;
ServerCommandHandler* g_handler = nullptr; // Глобальный указатель на обработчик

// Обработчик сигналов для корректного завершения
void signal_handler(int signal) {
    std::unique_lock<std::mutex> lock(g_mutex);
    g_running = false;
    std::cout << "\nПолучен сигнал завершения (" << signal << "). Останавливаем IDS..." << std::endl;
    
    // Если есть обработчик, останавливаем захват и сохраняем логи
    if (g_handler) {
        g_handler->stopCapture();
        
        // Генерируем имя файла с текущей датой и временем
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        char buffer[80];
        std::strftime(buffer, sizeof(buffer), "ids_log_%Y%m%d_%H%M%S.enc", std::localtime(&time));
        std::string filename = buffer;
        
        // Сохраняем логи перед завершением
        g_handler->saveLogsToFile(filename);
    }
    
    g_cv.notify_all();
}

// Форматирование сообщений для вывода в консоль
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t time = std::chrono::system_clock::to_time_t(now);
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
    return std::string(buffer);
}

// Конструктор
ServerCommandHandler::ServerCommandHandler()
    : m_packetHandler(new SimplePacketHandler()),
      m_deviceManager(new DeviceManagerConsole(nullptr)),
      m_suspiciousIPModel(new ServerSuspiciousIPModel(nullptr)),
      m_isCapturing(false),
      m_totalPacketsDetected(0),
      m_totalAlertsDetected(0),
      m_lastDeviceIndex(-1),
      m_verboseMode(false),
      m_encryptionEnabled(false),
      m_autoSaveCounter(0) {
    
    // Регистрируем этот экземпляр как глобальный для обработки сигналов
    g_handler = this;
    
    // Устанавливаем обработчик сигналов для корректного завершения
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Устанавливаем обработчик для обнаружения пакетов
    m_packetHandler->setPacketDetectedCallback(
        std::bind(&ServerCommandHandler::onPacketDetected, this, 
                 std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, 
                 std::placeholders::_4, std::placeholders::_5));
                    
    // Инициализируем список подозрительных IP-адресов
    m_suspiciousIPs.clear();
}

// Деструктор
ServerCommandHandler::~ServerCommandHandler() {
    stopCapture();
    
    // Сохраняем логи перед завершением, если включено шифрование
    if (m_encryptionEnabled) {
        // Генерируем имя файла с текущей датой и временем
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        char buffer[80];
        std::strftime(buffer, sizeof(buffer), "ids_log_%Y%m%d_%H%M%S.enc", std::localtime(&time));
        std::string filename = buffer;
        
        // Сохраняем логи перед завершением
        saveLogsToFile(filename);
    }
    
    // Удаляем объекты
    delete m_packetHandler;
    delete m_deviceManager;
    delete m_suspiciousIPModel;
    
    // Очищаем глобальный указатель
    g_handler = nullptr;
}

// Установка пароля шифрования
void ServerCommandHandler::setEncryptionPassword(const std::string& password) {
    if (!password.empty()) {
        m_encryptionPassword = password;
        m_encryptionEnabled = true;
        std::cout << "[" << get_timestamp() << "] Шифрование логов включено" << std::endl;
        
        // Запускаем таймер для автосохранения логов каждые 5 минут
        m_autoSaveTimer = std::thread([this]() {
            while (m_encryptionEnabled && g_running) {
                // Спим 5 минут
                for (int i = 0; i < 300 && g_running && m_encryptionEnabled; i++) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                
                if (m_encryptionEnabled && g_running) {
                    // Генерируем имя файла с текущей датой и временем
                    auto now = std::chrono::system_clock::now();
                    std::time_t time = std::chrono::system_clock::to_time_t(now);
                    char buffer[80];
                    std::strftime(buffer, sizeof(buffer), "ids_log_%Y%m%d_%H%M%S.enc", std::localtime(&time));
                    std::string filename = buffer;
                    
                    // Автоматически сохраняем логи
                    std::cout << "[" << get_timestamp() << "] Автоматическое сохранение логов..." << std::endl;
                    saveLogsToFile(filename);
                }
            }
        });
        m_autoSaveTimer.detach();
    } else {
        m_encryptionEnabled = false;
        m_encryptionPassword.clear();
        std::cout << "[" << get_timestamp() << "] Шифрование логов отключено" << std::endl;
    }
}

// Запуск захвата пакетов
bool ServerCommandHandler::startCapture(int deviceIndex) {
    if (m_isCapturing) {
        std::cout << "[" << get_timestamp() << "] Захват пакетов уже запущен" << std::endl;
        return false;
    }
    
    // Получаем имя устройства по индексу
    std::string deviceName = m_deviceManager->getDeviceNameByIndex(deviceIndex);
    
    if (deviceName.empty()) {
        std::cout << "[" << get_timestamp() << "] Ошибка: Не удалось получить имя устройства" << std::endl;
        return false;
    }
    
    std::cout << "[" << get_timestamp() << "] Выбранное устройство: " << deviceName << std::endl;
    
    // Проверяем, выбран ли тестовый адаптер
    if (deviceName == "test0") {
        std::cout << "[" << get_timestamp() << "] Тестовый режим активирован..." << std::endl;
        m_isCapturing = true;
        m_lastDeviceIndex = deviceIndex;
        
        // Запускаем тестовый режим в отдельном потоке
        m_captureThread = std::thread([this]() {
            while (g_running && m_isCapturing) {
                generateTestTraffic();
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        });
        
        return true;
    }
    
    // Пробуем запустить захват пакетов
    std::string errorMessage;
    if (m_packetHandler->startCapture(deviceName, &errorMessage)) {
        m_isCapturing = true;
        m_lastDeviceIndex = deviceIndex;
        
        std::cout << "[" << get_timestamp() << "] Захват пакетов запущен на интерфейсе " << deviceName << std::endl;
        std::cout << "[" << get_timestamp() << "] Система IDS активирована в режиме мониторинга" << std::endl;
        
        return true;
    } else {
        std::cout << "[" << get_timestamp() << "] Ошибка: Не удалось запустить захват пакетов" << std::endl;
        if (!errorMessage.empty()) {
            std::cout << "Причина: " << errorMessage << std::endl;
        }
        
        std::cout << "Возможные причины:" << std::endl;
        std::cout << "1. Npcap/libpcap не установлен или установлен неправильно" << std::endl;
        std::cout << "2. У приложения недостаточно прав (запустите от имени root/администратора)" << std::endl;
        std::cout << "3. Выбранный сетевой адаптер недоступен или не поддерживается" << std::endl;
        std::cout << "4. Другое приложение уже использует этот адаптер" << std::endl;
        std::cout << "5. Сетевой адаптер не поддерживает режим promiscuous" << std::endl;
        
        return false;
    }
}

// Остановка захвата пакетов
void ServerCommandHandler::stopCapture() {
    if (!m_isCapturing) {
        std::cout << "[" << get_timestamp() << "] Захват пакетов не был запущен" << std::endl;
        return;
    }
    
    // Если был запущен тестовый режим
    if (m_deviceManager->getDeviceNameByIndex(m_lastDeviceIndex) == "test0") {
        m_isCapturing = false;
        if (m_captureThread.joinable()) {
            m_captureThread.join();
        }
    } else {
        m_packetHandler->stopCapture();
    }
    
    m_isCapturing = false;
    std::cout << "[" << get_timestamp() << "] Захват пакетов остановлен" << std::endl;
}

// Обработчик обнаружения пакета
void ServerCommandHandler::onPacketDetected(const std::string& srcMAC, const std::string& dstMAC,
                                     const std::string& packetInfo, const std::string& timestamp,
                                     bool isPotentialThreat) {
    m_totalPacketsDetected++;

    // Если это угроза, выводим информацию и сохраняем IP в список подозрительных
    if (isPotentialThreat) {
        m_totalAlertsDetected++;
        
        std::cout << "[" << get_timestamp() << "] [ALERT] " << packetInfo << std::endl;
        
        // Извлекаем IP-адрес из строки информации о пакете
        size_t pos = packetInfo.find("IP: ");
        if (pos != std::string::npos) {
            std::string ip = packetInfo.substr(pos + 4);
            pos = ip.find(' ');
            if (pos != std::string::npos) {
                ip = ip.substr(0, pos);
                
                // Добавляем в список подозрительных IP с текущим временем
                m_suspiciousIPs[ip] = get_timestamp();
                
                // Добавляем в модель подозрительных IP
                m_suspiciousIPModel->addRecord(ip, packetInfo, false);
            }
        }
        
        // Если включена автоматическая запись логов при обнаружении угроз
        if (m_encryptionEnabled) {
            m_autoSaveCounter++;
            
            // Автоматически сохраняем логи каждые 10 обнаруженных угроз
            if (m_autoSaveCounter >= 10) {
                m_autoSaveCounter = 0;
                
                // Генерируем имя файла с текущей датой и временем
                auto now = std::chrono::system_clock::now();
                std::time_t time = std::chrono::system_clock::to_time_t(now);
                char buffer[80];
                std::strftime(buffer, sizeof(buffer), "ids_log_%Y%m%d_%H%M%S.enc", std::localtime(&time));
                std::string filename = buffer;
                
                // Автоматически сохраняем логи при обнаружении угроз
                std::cout << "[" << get_timestamp() << "] Автоматическое сохранение логов после обнаружения угроз..." << std::endl;
                saveLogsToFile(filename);
            }
        }
    } else if (m_verboseMode) {
        // В подробном режиме выводим информацию о всех пакетах
        std::cout << "[" << get_timestamp() << "] [INFO] " << packetInfo << std::endl;
    }
    
    // Каждые 1000 пакетов выводим статистику
    if (m_totalPacketsDetected % 1000 == 0) {
        printStatistics();
    }
}

// Генерация тестового трафика
void ServerCommandHandler::generateTestTraffic() {
    static int counter = 0;
    counter++;
    
    // Генерируем случайный IP и выбираем тип атаки
    std::string srcIP = "192.168.1." + std::to_string(std::rand() % 254 + 1);
    std::string dstIP = "10.0.0." + std::to_string(std::rand() % 254 + 1);
    
    std::string srcMAC = "00:11:22:33:44:55";
    std::string dstMAC = "AA:BB:CC:DD:EE:FF";
    std::string timestamp = get_timestamp();
    
    bool isPotentialThreat = (counter % 10 == 0); // Каждый 10-й пакет - потенциальная угроза
    std::string packetInfo;
    
    if (isPotentialThreat) {
        // Генерируем различные типы атак
        int attackType = std::rand() % 4;
        switch (attackType) {
            case 0:
                packetInfo = "Обнаружена попытка сканирования портов с IP: " + srcIP + " (порты 20-80)";
                break;
            case 1:
                packetInfo = "Обнаружена SYN-флуд атака с IP: " + srcIP + " на порт 80";
                break;
            case 2:
                packetInfo = "Обнаружена подозрительная активность с IP: " + srcIP + " (множественные запросы)";
                break;
            case 3:
                packetInfo = "Обнаружена попытка брутфорс-атаки с IP: " + srcIP + " на SSH-порт";
                break;
        }
    } else {
        packetInfo = "TCP пакет от " + srcIP + " к " + dstIP + ", порт 80";
    }
    
    // Вызываем обработчик пакета
    onPacketDetected(srcMAC, dstMAC, packetInfo, timestamp, isPotentialThreat);
}

// Вывод статистики
void ServerCommandHandler::printStatistics() {
    std::cout << "\n===== Статистика IDS =====" << std::endl;
    std::cout << "Время: " << get_timestamp() << std::endl;
    std::cout << "Всего обработано пакетов: " << m_totalPacketsDetected << std::endl;
    std::cout << "Обнаружено потенциальных угроз: " << m_totalAlertsDetected << std::endl;
    std::cout << "Активные подозрительные IP: " << m_suspiciousIPs.size() << std::endl;
    std::cout << "Подозрительные IP в модели: " << m_suspiciousIPModel->getRecordCount() << std::endl;
    std::cout << "Статус захвата: " << (m_isCapturing ? "Активен" : "Неактивен") << std::endl;
    std::cout << "Шифрование логов: " << (m_encryptionEnabled ? "Включено" : "Отключено") << std::endl;
    if (m_isCapturing) {
        std::cout << "Интерфейс: " << m_deviceManager->getDeviceNameByIndex(m_lastDeviceIndex) << std::endl;
    }
    std::cout << "=========================\n" << std::endl;
}

// Вывод списка подозрительных IP-адресов
void ServerCommandHandler::printSuspiciousIPs() {
    if (m_suspiciousIPs.empty()) {
        std::cout << "[" << get_timestamp() << "] Подозрительные IP-адреса не обнаружены" << std::endl;
        return;
    }
    
    std::cout << "\n===== Подозрительные IP-адреса =====" << std::endl;
    for (const auto& pair : m_suspiciousIPs) {
        std::cout << "IP: " << pair.first << " | Последняя активность: " << pair.second << std::endl;
        
        // Выводим дополнительную информацию из модели
        std::string ipInfo = m_suspiciousIPModel->getInfoAboutIP(pair.first);
        if (ipInfo != "Информация об IP не найдена") {
            std::cout << "  Дополнительно: " << ipInfo << std::endl;
        }
    }
    std::cout << "====================================\n" << std::endl;
}

// Вывод списка доступных сетевых интерфейсов
void ServerCommandHandler::printDeviceList() {
    auto deviceList = m_deviceManager->getDeviceList();
    
    std::cout << "\n===== Доступные сетевые интерфейсы =====" << std::endl;
    for (size_t i = 0; i < deviceList.size(); i++) {
        std::cout << i << ": " << deviceList[i] << std::endl;
    }
    std::cout << "========================================\n" << std::endl;
}

// Сохранение лога в файл
bool ServerCommandHandler::saveLogsToFile(const std::string& fileName) {
    // Подготавливаем содержимое лога
    std::stringstream content;
    content << "===== Лог системы обнаружения вторжений =====" << std::endl;
    content << "Дата создания: " << get_timestamp() << std::endl;
    content << "Всего обработано пакетов: " << m_totalPacketsDetected << std::endl;
    content << "Обнаружено потенциальных угроз: " << m_totalAlertsDetected << std::endl << std::endl;
    
    content << "===== Подозрительные IP-адреса =====" << std::endl;
    for (const auto& pair : m_suspiciousIPs) {
        content << "IP: " << pair.first << " | Последняя активность: " << pair.second << std::endl;
    }
    
    std::string contentStr = content.str();
    std::ofstream file;
    
    // Если включено шифрование, шифруем лог
    if (m_encryptionEnabled) {
        // Генерируем ключ из пароля
        std::vector<unsigned char> key = ConsoleLogEncryption::generateKey(m_encryptionPassword);
        
        // Преобразуем строку в вектор байтов
        std::vector<unsigned char> data = ConsoleLogEncryption::stringToBytes(contentStr);
        
        // Шифруем данные
        std::vector<unsigned char> encrypted = ConsoleLogEncryption::encrypt(data, key);
        
        // Сохраняем зашифрованный лог
        file.open(fileName, std::ios::binary);
        if (!file.is_open()) {
            std::cout << "[" << get_timestamp() << "] Ошибка: Не удалось открыть файл " << fileName << std::endl;
            return false;
        }
        
        // Записываем зашифрованные данные
        file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        
        std::cout << "[" << get_timestamp() << "] Лог успешно зашифрован и сохранен в файл " << fileName << std::endl;
    } else {
        // Сохраняем в обычном текстовом формате
        file.open(fileName);
        if (!file.is_open()) {
            std::cout << "[" << get_timestamp() << "] Ошибка: Не удалось открыть файл " << fileName << std::endl;
            return false;
        }
        
        file << contentStr;
        std::cout << "[" << get_timestamp() << "] Лог успешно сохранен в файл " << fileName << std::endl;
    }
    
    file.close();
    return true;
}

// Установка режима подробного вывода
void ServerCommandHandler::setVerboseMode(bool mode) {
    m_verboseMode = mode;
    std::cout << "[" << get_timestamp() << "] Режим подробного вывода " 
              << (mode ? "включен" : "выключен") << std::endl;
}

// Добавим функцию для расшифровки логов
bool ServerCommandHandler::decryptLogsFromFile(const std::string& fileName) {
    // Проверяем, что файл существует
    std::ifstream testFile(fileName);
    if (!testFile.good()) {
        std::cout << "[" << get_timestamp() << "] Ошибка: Файл " << fileName << " не найден" << std::endl;
        return false;
    }
    testFile.close();
    
    // Если не установлен пароль или шифрование отключено, запрашиваем пароль у пользователя
    std::string decryptionPassword = m_encryptionPassword;
    if (decryptionPassword.empty() || !m_encryptionEnabled) {
        std::cout << "Введите пароль для расшифровки файла: ";
        // Отключаем эхо-вывод для безопасности (только в Unix-системах)
        #ifndef _WIN32
        system("stty -echo");
        #endif
        
        std::getline(std::cin, decryptionPassword);
        
        // Включаем эхо-вывод обратно
        #ifndef _WIN32
        system("stty echo");
        #endif
        
        std::cout << std::endl; // Перевод строки после ввода пароля
        
        if (decryptionPassword.empty()) {
            std::cout << "[" << get_timestamp() << "] Ошибка: Пароль не может быть пустым" << std::endl;
            return false;
        }
    }
    
    // Открываем файл для чтения
    std::ifstream file(fileName, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "[" << get_timestamp() << "] Ошибка: Не удалось открыть файл " << fileName << std::endl;
        return false;
    }
    
    // Читаем содержимое файла в вектор
    std::vector<unsigned char> encryptedData(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    file.close();
    
    if (encryptedData.empty()) {
        std::cout << "[" << get_timestamp() << "] Ошибка: Файл пуст или повреждён" << std::endl;
        return false;
    }
    
    try {
        // Генерируем ключ из пароля
        std::vector<unsigned char> key = ConsoleLogEncryption::generateKey(decryptionPassword);
        
        // Расшифровываем данные
        std::vector<unsigned char> decrypted = ConsoleLogEncryption::decrypt(encryptedData, key);
        
        // Преобразуем в строку и выводим
        std::string decryptedStr = ConsoleLogEncryption::bytesToString(decrypted);
        
        std::cout << "\n===== Расшифрованный лог =====" << std::endl;
        std::cout << decryptedStr << std::endl;
        std::cout << "=============================\n" << std::endl;
        
        return true;
    } catch (const std::exception& e) {
        std::cout << "[" << get_timestamp() << "] Ошибка при расшифровке: " << e.what() << std::endl;
        std::cout << "Возможно, неверный пароль или формат файла" << std::endl;
        
        // Предлагаем пользователю попробовать другой пароль
        std::cout << "Хотите попробовать другой пароль? (y/n): ";
        std::string response;
        std::getline(std::cin, response);
        
        if (response == "y" || response == "Y" || response == "д" || response == "Д") {
            // Рекурсивно вызываем ту же функцию с пустым паролем, чтобы запросить его заново
            m_encryptionPassword = ""; // Сбрасываем текущий пароль
            return decryptLogsFromFile(fileName);
        }
        
        return false;
    }
    
    return false;
}

// Обработка команд пользователя
void ServerCommandHandler::processCommand(const std::string& commandLine) {
    std::istringstream iss(commandLine);
    std::string command;
    iss >> command;
    
    // Преобразуем команду к нижнему регистру
    std::transform(command.begin(), command.end(), command.begin(),
                  [](unsigned char c){ return std::tolower(c); });
    
    if (command == "help" || command == "?") {
        printHelp();
    } else if (command == "start") {
        int deviceIndex = -1;
        iss >> deviceIndex;
        
        if (deviceIndex < 0) {
            if (m_lastDeviceIndex >= 0) {
                deviceIndex = m_lastDeviceIndex;
            } else {
                std::cout << "Ошибка: Не указан индекс устройства. Используйте: start <индекс>" << std::endl;
                return;
            }
        }
        
        startCapture(deviceIndex);
    } else if (command == "stop") {
        stopCapture();
    } else if (command == "devices" || command == "list") {
        printDeviceList();
    } else if (command == "stats" || command == "status") {
        printStatistics();
    } else if (command == "ips") {
        printSuspiciousIPs();
    } else if (command == "save") {
        std::string fileName;
        iss >> fileName;
        
        if (fileName.empty()) {
            // Генерируем имя файла с текущей датой и временем
            auto now = std::chrono::system_clock::now();
            std::time_t time = std::chrono::system_clock::to_time_t(now);
            char buffer[80];
            std::strftime(buffer, sizeof(buffer), "ids_log_%Y%m%d_%H%M%S.txt", std::localtime(&time));
            fileName = buffer;
        }
        
        saveLogsToFile(fileName);
    } else if (command == "verbose" || command == "debug") {
        std::string mode;
        iss >> mode;
        
        if (mode == "on" || mode == "1") {
            setVerboseMode(true);
        } else if (mode == "off" || mode == "0") {
            setVerboseMode(false);
        } else {
            // Переключаем режим
            setVerboseMode(!m_verboseMode);
        }
    } else if (command == "encrypt") {
        std::string password;
        iss >> password;
        
        if (password.empty()) {
            std::cout << "Введите пароль для шифрования: ";
            std::getline(std::cin, password);
        }
        
        setEncryptionPassword(password);
    } else if (command == "decrypt") {
        std::string fileName;
        iss >> fileName;
        
        if (fileName.empty()) {
            std::cout << "Введите имя файла для расшифровки: ";
            std::getline(std::cin, fileName);
        }
        
        decryptLogsFromFile(fileName);
    } else if (command == "clear") {
        // Очищаем список подозрительных IP
        m_suspiciousIPs.clear();
        m_suspiciousIPModel->clearRecords();
        std::cout << "[" << get_timestamp() << "] Список подозрительных IP-адресов очищен" << std::endl;
    } else if (command == "exit" || command == "quit") {
        g_running = false;
        g_cv.notify_all();
    } else {
        std::cout << "Неизвестная команда: " << command << std::endl;
        std::cout << "Введите 'help' для получения списка доступных команд" << std::endl;
    }
}

// Вывод справки по командам
void ServerCommandHandler::printHelp() {
    std::cout << "\n===== Доступные команды =====" << std::endl;
    std::cout << "help, ?            - Показать список команд" << std::endl;
    std::cout << "devices, list      - Показать список доступных сетевых интерфейсов" << std::endl;
    std::cout << "start <индекс>     - Запустить захват пакетов на указанном интерфейсе" << std::endl;
    std::cout << "stop               - Остановить захват пакетов" << std::endl;
    std::cout << "stats, status      - Показать текущую статистику" << std::endl;
    std::cout << "ips                - Показать список подозрительных IP-адресов" << std::endl;
    std::cout << "save [имя_файла]   - Сохранить лог в файл (по умолчанию ids_log_дата_время.txt)" << std::endl;
    std::cout << "encrypt [пароль]   - Установить пароль для шифрования логов" << std::endl;
    std::cout << "decrypt <файл>     - Расшифровать и показать лог из файла" << std::endl;
    std::cout << "verbose, debug     - Переключить режим подробного вывода" << std::endl;
    std::cout << "clear              - Очистить список подозрительных IP-адресов" << std::endl;
    std::cout << "exit, quit         - Выйти из программы" << std::endl;
    std::cout << "=============================\n" << std::endl;
}

// Запуск интерактивного режима
void ServerCommandHandler::runInteractive() {
    std::cout << "=== Система обнаружения вторжений (SSH-режим) ===" << std::endl;
    std::cout << "Введите 'help' для получения списка доступных команд" << std::endl;
    
    // Запрашиваем пароль для шифрования логов при запуске
    std::cout << "Введите пароль для шифрования логов (оставьте пустым, чтобы отключить шифрование): ";
    std::string password;
    std::getline(std::cin, password);
    setEncryptionPassword(password);
    
    // Выводим список доступных устройств
    printDeviceList();
    
    std::string line;
    std::unique_lock<std::mutex> lock(g_mutex, std::defer_lock);
    while (g_running) {
        std::cout << "IDS> ";
        std::getline(std::cin, line);
        
        if (!line.empty()) {
            processCommand(line);
        }
        
        // Проверяем сигнал выхода
        lock.lock();
        if (!g_running) {
            lock.unlock();
            break;
        }
        lock.unlock();
    }
    
    // Останавливаем захват, если он был активен
    if (m_isCapturing) {
        stopCapture();
    }
    
    std::cout << "Система обнаружения вторжений завершает работу." << std::endl;
} 