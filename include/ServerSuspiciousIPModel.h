#ifndef SERVER_SUSPICIOUS_IP_MODEL_H
#define SERVER_SUSPICIOUS_IP_MODEL_H

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

/**
 * @brief Класс для хранения информации о подозрительных IP-адресах (консольная версия)
 */
class ServerSuspiciousIPModel {
public:
    /**
     * @brief Структура для хранения записи о подозрительном IP
     */
    struct Record {
        std::string ip;
        std::string description;
        std::string timestamp;
        bool blocked;
        
        Record(const std::string& _ip = "",
               const std::string& _desc = "",
               bool _blocked = false)
            : ip(_ip), description(_desc), blocked(_blocked) {
        }
    };
    
    /**
     * @brief Конструктор
     */
    ServerSuspiciousIPModel(void* parent = nullptr)
        : m_records() {
    }
    
    /**
     * @brief Деструктор
     */
    ~ServerSuspiciousIPModel() {
    }
    
    /**
     * @brief Получение количества записей
     */
    int getRecordCount() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_records.size();
    }
    
    /**
     * @brief Добавление новой записи
     */
    void addRecord(const std::string& ip, const std::string& description, bool blocked = false) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Проверяем, есть ли уже запись с таким IP
        for (auto& record : m_records) {
            if (record.ip == ip) {
                // Обновляем информацию
                record.description = description;
                record.blocked = blocked;
                return;
            }
        }
        
        // Добавляем новую запись
        m_records.push_back(Record(ip, description, blocked));
    }
    
    /**
     * @brief Получение списка IP-адресов
     */
    std::vector<std::string> getIPList() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<std::string> result;
        
        for (const auto& record : m_records) {
            result.push_back(record.ip);
        }
        
        return result;
    }
    
    /**
     * @brief Блокировка IP-адреса
     */
    void blockIP(const std::string& ip, bool block = true) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (auto& record : m_records) {
            if (record.ip == ip) {
                record.blocked = block;
                break;
            }
        }
    }
    
    /**
     * @brief Получение информации о блокировке IP-адреса
     */
    bool isBlocked(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (const auto& record : m_records) {
            if (record.ip == ip) {
                return record.blocked;
            }
        }
        
        return false;
    }
    
    /**
     * @brief Получение информации об IP-адресе
     */
    std::string getInfoAboutIP(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        for (const auto& record : m_records) {
            if (record.ip == ip) {
                return record.description;
            }
        }
        
        return "Информация об IP не найдена";
    }
    
    /**
     * @brief Очистка всех записей
     */
    void clearRecords() {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_records.clear();
    }
    
    /**
     * @brief Очистка всех записей (альтернативное имя метода)
     */
    void clear() {
        clearRecords();
    }
    
private:
    std::vector<Record> m_records;
    mutable std::mutex m_mutex;
};

#endif // SERVER_SUSPICIOUS_IP_MODEL_H 