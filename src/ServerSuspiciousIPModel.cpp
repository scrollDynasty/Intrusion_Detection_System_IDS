#include "ServerSuspiciousIPModel.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iostream>
#include <iomanip>

// Вспомогательная функция для получения текущего времени
static std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// Вспомогательная функция для логирования
static void logSuspiciousIP(const std::string& ip, const std::string& reason) {
    std::cout << "[" << getCurrentTimestamp() << "] Подозрительный IP добавлен: " 
              << ip << " (" << reason << ")" << std::endl;
} 