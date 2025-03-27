#ifndef DEVICE_MANAGER_CONSOLE_H
#define DEVICE_MANAGER_CONSOLE_H

#include <string>
#include <vector>
#include <pcap.h>

/**
 * @brief Класс для управления сетевыми интерфейсами в консольном режиме
 */
class DeviceManagerConsole {
public:
    /**
     * @brief Конструктор
     */
    DeviceManagerConsole(void* parent = nullptr);
    
    /**
     * @brief Деструктор
     */
    ~DeviceManagerConsole();
    
    /**
     * @brief Получение списка доступных устройств
     * @return Вектор имен устройств
     */
    std::vector<std::string> getDeviceList();
    
    /**
     * @brief Получение имени устройства по индексу
     * @param index Индекс устройства
     * @return Имя устройства или пустая строка, если не найдено
     */
    std::string getDeviceNameByIndex(int index);
    
    /**
     * @brief Получение описания устройства по индексу
     * @param index Индекс устройства
     * @return Описание устройства или пустая строка, если не найдено
     */
    std::string getDeviceDescriptionByIndex(int index);
    
    /**
     * @brief Получение IP-адреса устройства по индексу
     * @param index Индекс устройства
     * @return IP-адрес устройства или пустая строка, если не найдено
     */
    std::string getDeviceIPByIndex(int index);
    
    /**
     * @brief Получение MAC-адреса устройства по индексу
     * @param index Индекс устройства
     * @return MAC-адрес устройства или пустая строка, если не найдено
     */
    std::string getDeviceMACByIndex(int index);
    
    /**
     * @brief Добавление тестового устройства
     */
    void addTestDevice();
    
private:
    struct Device {
        std::string name;
        std::string description;
        std::string ip;
        std::string mac;
        
        Device(const std::string& _name = "", 
               const std::string& _desc = "", 
               const std::string& _ip = "", 
               const std::string& _mac = "")
            : name(_name), description(_desc), ip(_ip), mac(_mac) {
        }
    };
    
    /**
     * @brief Обновление списка устройств
     */
    void refreshDeviceList();
    
    std::vector<Device> m_devices;  // Список устройств
    bool m_devicesRefreshed;        // Флаг обновления списка устройств
};

#endif // DEVICE_MANAGER_CONSOLE_H 