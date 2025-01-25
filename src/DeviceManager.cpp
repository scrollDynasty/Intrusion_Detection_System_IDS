#include "DeviceManager.h"
#include <iostream>
#include <pcap.h>

std::string DeviceManager::chooseDevice() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* allDevices;
    if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
        std::cerr << "Error: " << errorBuffer << std::endl;
        return "";
    }

    std::cout << "Available devices:" << std::endl;
    int deviceCount = 0;
    for (pcap_if_t* device = allDevices; device != nullptr; device = device->next) {
        std::cout << ++deviceCount << ". " << device->name;
        if (device->description) {
            std::cout << " (" << device->description << ")";
        }
        std::cout << std::endl;
    }

    if (deviceCount == 0) {
        std::cerr << "No devices available!" << std::endl;
        return "";
    }

    std::cout << "Enter device number: ";
    int choice;
    std::cin >> choice;

    pcap_if_t* selectedDevice = allDevices;
    for (int i = 1; i < choice; ++i) {
        selectedDevice = selectedDevice->next;
    }

    std::string deviceName = selectedDevice->name;
    pcap_freealldevs(allDevices);

    return deviceName;
}
