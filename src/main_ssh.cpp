#include <iostream>
#include <string>
#include <signal.h>
#include "ServerCommandHandler.h"

// Функция для вывода помощи
void print_help(const char* program_name) {
    std::cout << "Использование: " << program_name << " [ОПЦИИ]" << std::endl;
    std::cout << "Опции:" << std::endl;
    std::cout << "  -a, --adapter <индекс>   Индекс сетевого интерфейса" << std::endl;
    std::cout << "  -v, --verbose            Включить подробный режим вывода" << std::endl;
    std::cout << "  -t, --test               Запустить в тестовом режиме" << std::endl;
    std::cout << "  -s, --service            Запустить как системный сервис" << std::endl;
    std::cout << "  -e, --encrypt <пароль>   Установить пароль шифрования" << std::endl;
    std::cout << "  -h, --help               Показать эту справку" << std::endl;
    std::cout << "  --version                Показать версию программы" << std::endl;
}

// Функция для вывода версии
void print_version() {
    std::cout << "Система обнаружения вторжений (IDS-SSH) версия 1.0.0" << std::endl;
    std::cout << "Сборка: " << __DATE__ << " " << __TIME__ << std::endl;
}

int main(int argc, char *argv[]) {
    // Установка локали для корректного отображения кириллицы
    std::setlocale(LC_ALL, "");
    
    // Игнорируем SIGPIPE, чтобы программа не завершалась при обрыве соединения
    signal(SIGPIPE, SIG_IGN);
    
    // Парсим аргументы командной строки
    int adapter_index = -1;
    bool verbose_mode = false;
    bool test_mode = false;
    bool service_mode = false;
    std::string encryption_password;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-a" || arg == "--adapter") {
            if (i + 1 < argc) {
                adapter_index = std::stoi(argv[++i]);
            } else {
                std::cerr << "Ошибка: опция --adapter требует аргумент" << std::endl;
                return 1;
            }
        } else if (arg == "-v" || arg == "--verbose") {
            verbose_mode = true;
        } else if (arg == "-t" || arg == "--test") {
            test_mode = true;
            adapter_index = 0; // Тестовый адаптер имеет индекс 0
        } else if (arg == "-s" || arg == "--service") {
            service_mode = true;
        } else if (arg == "-e" || arg == "--encrypt") {
            if (i + 1 < argc) {
                encryption_password = argv[++i];
            } else {
                std::cerr << "Ошибка: опция --encrypt требует аргумент" << std::endl;
                return 1;
            }
        } else if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--version") {
            print_version();
            return 0;
        } else {
            std::cerr << "Неизвестная опция: " << arg << std::endl;
            print_help(argv[0]);
            return 1;
        }
    }
    
    // Создаем обработчик команд
    ServerCommandHandler commander;
    
    // Устанавливаем параметры
    if (verbose_mode) {
        commander.setVerboseMode(true);
    }
    
    if (!encryption_password.empty()) {
        commander.setEncryptionPassword(encryption_password);
    }
    
    // Запускаем захват на указанном интерфейсе, если задан
    if (adapter_index >= 0) {
        commander.startCapture(adapter_index);
    }
    
    // В зависимости от режима запуска
    if (service_mode) {
        // В режиме сервиса просто ждем событий
        std::cout << "IDS запущена в режиме сервиса." << std::endl;
        
        while(true) {
            // Бесконечный цикл, прерываемый сигналами
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } else {
        // Запускаем интерактивный режим
        commander.runInteractive();
    }
    
    return 0;
} 