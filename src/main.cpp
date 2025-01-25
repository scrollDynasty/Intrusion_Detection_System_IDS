#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <iostream>
#include <string>
#include "DeviceManager.h"
#include "PacketHandler.h"

#pragma comment(lib, "Ws2_32.lib")

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::cout << "Launching the Intrusion Detection System (IDS)" << std::endl;

    DeviceManager deviceManager;
    std::string deviceName = deviceManager.chooseDevice();
    if (deviceName.empty()) {
        std::cerr << "Failed to select device!" << std::endl;
        return 1;
    }

    PacketHandler packetHandler;
    if (!packetHandler.startCapture(deviceName)) {
        std::cerr << "Error starting packet capture!" << std::endl;
        return 1;
    }

    return 0;
}
