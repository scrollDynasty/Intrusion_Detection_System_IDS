#include "DeviceManagerConsole.h"
#include <iostream>
#include <sstream>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#endif

// Конструктор
DeviceManagerConsole::DeviceManagerConsole(void* parent)
    : m_devicesRefreshed(false) {
    // Добавляем тестовое устройство
    addTestDevice();
}

// Деструктор
DeviceManagerConsole::~DeviceManagerConsole() {
}

// Получение списка доступных устройств
std::vector<std::string> DeviceManagerConsole::getDeviceList() {
    if (!m_devicesRefreshed) {
        refreshDeviceList();
    }
    
    std::vector<std::string> devices;
    for (const auto& device : m_devices) {
        std::string deviceInfo = device.name;
        if (!device.description.empty()) {
            deviceInfo += " (" + device.description + ")";
        }
        devices.push_back(deviceInfo);
    }
    
    return devices;
}

// Получение имени устройства по индексу
std::string DeviceManagerConsole::getDeviceNameByIndex(int index) {
    if (!m_devicesRefreshed) {
        refreshDeviceList();
    }
    
    if (index >= 0 && index < static_cast<int>(m_devices.size())) {
        return m_devices[index].name;
    }
    
    return "";
}

// Получение описания устройства по индексу
std::string DeviceManagerConsole::getDeviceDescriptionByIndex(int index) {
    if (!m_devicesRefreshed) {
        refreshDeviceList();
    }
    
    if (index >= 0 && index < static_cast<int>(m_devices.size())) {
        return m_devices[index].description;
    }
    
    return "";
}

// Получение IP-адреса устройства по индексу
std::string DeviceManagerConsole::getDeviceIPByIndex(int index) {
    if (!m_devicesRefreshed) {
        refreshDeviceList();
    }
    
    if (index >= 0 && index < static_cast<int>(m_devices.size())) {
        return m_devices[index].ip;
    }
    
    return "";
}

// Получение MAC-адреса устройства по индексу
std::string DeviceManagerConsole::getDeviceMACByIndex(int index) {
    if (!m_devicesRefreshed) {
        refreshDeviceList();
    }
    
    if (index >= 0 && index < static_cast<int>(m_devices.size())) {
        return m_devices[index].mac;
    }
    
    return "";
}

// Добавление тестового устройства
void DeviceManagerConsole::addTestDevice() {
    Device testDevice;
    testDevice.name = "test0";
    testDevice.description = "Тестовый режим (симуляция)";
    testDevice.ip = "127.0.0.1";
    testDevice.mac = "00:00:00:00:00:00";
    
    m_devices.push_back(testDevice);
}

// Обновление списка устройств
void DeviceManagerConsole::refreshDeviceList() {
    m_devices.clear();
    
    // Добавляем тестовое устройство
    addTestDevice();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    // Получаем список устройств
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Ошибка при получении списка устройств: " << errbuf << std::endl;
        return;
    }
    
    // Проходим по списку устройств
    for (pcap_if_t* dev = alldevs; dev != nullptr; dev = dev->next) {
        Device device;
        device.name = dev->name;
        
        if (dev->description) {
            device.description = dev->description;
        } else {
            device.description = "Нет описания";
        }
        
        // Получаем IP-адрес
        for (pcap_addr_t* addr = dev->addresses; addr != nullptr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                device.ip = inet_ntoa(((struct sockaddr_in*)addr->addr)->sin_addr);
                break;
            }
        }
        
        // MAC-адрес получается по-разному в зависимости от ОС
        // В этой упрощенной версии оставим его пустым
        device.mac = "Unknown";
        
        m_devices.push_back(device);
    }
    
    // Освобождаем ресурсы
    pcap_freealldevs(alldevs);
    m_devicesRefreshed = true;
} 