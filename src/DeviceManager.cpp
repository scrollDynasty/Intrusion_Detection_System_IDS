#include "DeviceManager.h"
#include <iostream>
#include <pcap.h>
#include <QDebug>

DeviceManager::DeviceManager(QObject *parent) : QObject(parent) {
    // Инициализация
}

DeviceManager::~DeviceManager() {
    // Освобождение ресурсов
}

std::vector<std::string> DeviceManager::getDeviceList() {
    std::vector<std::string> deviceList;
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Получаем список всех устройств
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "Ошибка при получении списка устройств:" << errbuf;
        return deviceList;
    }
    
    // Добавляем тестовый адаптер
    deviceList.push_back("test0 (Тестовый режим)");
    deviceNamesMap[0] = "test0";
    
    int i = 1; // Начинаем с 1, так как 0 - тестовый адаптер
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::string name = d->name;
        std::string description = (d->description) ? d->description : "Нет описания";
        
        // Определяем тип адаптера (Wi-Fi, Ethernet и т.д.)
        std::string adapterType = "Неизвестно";
        
#ifdef _WIN32
        // Windows-специфичное определение типа адаптера
        if (description.find("Wi-Fi") != std::string::npos || 
            description.find("Wireless") != std::string::npos ||
            description.find("802.11") != std::string::npos) {
            adapterType = "Wi-Fi";
        } else if (description.find("Ethernet") != std::string::npos ||
                  description.find("LAN") != std::string::npos) {
            adapterType = "Ethernet";
        }
#else
        // Linux-специфичное определение типа адаптера
        if (name.find("wlan") != std::string::npos ||
            name.find("wifi") != std::string::npos) {
            adapterType = "Wi-Fi";
        } else if (name.find("eth") != std::string::npos ||
                  name.find("en") == 0) {
            adapterType = "Ethernet";
        } else if (name.find("lo") != std::string::npos) {
            adapterType = "Loopback";
        }
#endif
        
        // Формируем удобное имя для отображения
        std::string displayName = name + " (" + adapterType + ": " + description + ")";
        
        deviceList.push_back(displayName);
        deviceNamesMap[i] = name;
        i++;
    }
    
    // Освобождаем список устройств
    pcap_freealldevs(alldevs);
    
    return deviceList;
}

std::string DeviceManager::getDeviceNameByIndex(int index) {
    if (deviceNamesMap.find(index) != deviceNamesMap.end()) {
        return deviceNamesMap[index];
    }
    return "";
}
