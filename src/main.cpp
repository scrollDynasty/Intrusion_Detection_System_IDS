#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fcntl.h>
#include <io.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <iostream>
#include <string>
#include <vector>
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QDateTime>
#include <QMutex>
#include <termios.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "PacketHandler.h"

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

// Глобальный мьютекс для синхронизации доступа к файлу лога
QMutex logMutex;

// Глобальная переменная для хранения пароля шифрования
QString g_encryptionPassword;

// Функция для чтения пароля без отображения символов
std::string readPassword() {
    struct termios oldt, newt;
    std::string password;
    
    // Сохраняем текущие настройки терминала
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON);
    
    // Устанавливаем новые настройки
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    // Читаем пароль
    std::getline(std::cin, password);
    
    // Восстанавливаем старые настройки
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    
    return password;
}

// Обработчик сообщений для перенаправления вывода в зашифрованный файл лога
void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    QMutexLocker locker(&logMutex);
    
    QDateTime now = QDateTime::currentDateTime();
    QString timestamp = now.toString("yyyy-MM-dd hh:mm:ss.zzz");
    QString logMessage;
    
    switch (type) {
        case QtDebugMsg:
            logMessage = timestamp + " [DEBUG] " + msg + "\n";
            break;
        case QtInfoMsg:
            logMessage = timestamp + " [INFO] " + msg + "\n";
            break;
        case QtWarningMsg:
            logMessage = timestamp + " [WARNING] " + msg + "\n";
            break;
        case QtCriticalMsg:
            logMessage = timestamp + " [CRITICAL] " + msg + "\n";
            break;
        case QtFatalMsg:
            logMessage = timestamp + " [FATAL] " + msg + "\n";
            break;
    }
    
    // Шифруем сообщение
    QByteArray data = logMessage.toUtf8();
    QByteArray encrypted;
    encrypted.resize(data.size() + 16); // Размер блока AES
    
    // Используем тот же метод шифрования, что и в GUI
    unsigned char key[32];
    unsigned char iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                   (unsigned char*)g_encryptionPassword.toUtf8().constData(),
                   g_encryptionPassword.length(), 1, key, iv);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
        
        int len1, len2;
        EVP_EncryptUpdate(ctx, (unsigned char*)encrypted.data(), &len1,
                         (unsigned char*)data.constData(), data.size());
        EVP_EncryptFinal_ex(ctx, (unsigned char*)encrypted.data() + len1, &len2);
        
        encrypted.resize(len1 + len2);
        EVP_CIPHER_CTX_free(ctx);
        
        // Сохраняем в файл
        QFile logFile("ids_log.enc");
        if (logFile.open(QIODevice::Append)) {
            logFile.write(encrypted);
            logFile.close();
        }
    }
    
    // Выводим сообщение в консоль
    std::cout << qPrintable(msg) << std::endl;
}

// Функция для вывода списка доступных сетевых интерфейсов
void printAvailableInterfaces() {
    PacketHandler handler;
    std::vector<std::string> interfaces = handler.getAvailableInterfaces();
    
    std::cout << "\nДоступные сетевые интерфейсы:\n";
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << i + 1 << ". " << interfaces[i] << "\n";
    }
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);
    
    // Запрашиваем пароль в начале
    std::cout << "Введите пароль для шифрования логов: ";
    g_encryptionPassword = QString::fromStdString(readPassword());
    
    // Устанавливаем обработчик сообщений
    qInstallMessageHandler(messageHandler);
    
    // Настраиваем парсер командной строки
    QCommandLineParser parser;
    parser.setApplicationDescription("Intrusion Detection System (Консольная версия)");
    parser.addHelpOption();
    
    QCommandLineOption adapterOption(QStringList() << "a" << "adapter",
                                    "Указать сетевой интерфейс",
                                    "adapter");
    parser.addOption(adapterOption);
    
    parser.process(app);
    
    // Выводим главное меню
    static bool isMonitoring = false;
    static PacketHandler* packetHandler = nullptr;
    
    while (true) {
        std::cout << "\n=== Система обнаружения вторжений ===\n";
        std::cout << "1. Начать мониторинг\n";
        std::cout << "2. " << (isMonitoring ? "Остановить мониторинг" : "Мониторинг не запущен") << "\n";
        std::cout << "3. Изменить пароль шифрования\n";
        std::cout << "4. Выход\n";
        std::cout << "Выберите действие (1-4): ";
        
        int choice;
        std::cin >> choice;
        std::cin.ignore();
        
        switch (choice) {
            case 1: {
                if (isMonitoring) {
                    std::cout << "Мониторинг уже запущен!\n";
                    break;
                }
                
                // Показываем доступные интерфейсы
                PacketHandler tempHandler;
                std::vector<std::string> interfaces = tempHandler.getAvailableInterfaces();
                std::cout << "\nДоступные сетевые интерфейсы:\n";
                for (size_t i = 0; i < interfaces.size(); ++i) {
                    std::cout << i + 1 << ". " << interfaces[i] << "\n";
                }
                
                // Запрашиваем выбор интерфейса
                std::cout << "\nВыберите интерфейс (1-" << interfaces.size() << "): ";
                int interfaceChoice;
                std::cin >> interfaceChoice;
                std::cin.ignore();
                
                if (interfaceChoice < 1 || interfaceChoice > static_cast<int>(interfaces.size())) {
                    std::cout << "Неверный выбор интерфейса!\n";
                    break;
                }
                
                QString adapterName = QString::fromStdString(interfaces[interfaceChoice - 1]);
                
                packetHandler = new PacketHandler();
                QString errorMessage;
                if (packetHandler->startCapture(adapterName.toStdString(), &errorMessage)) {
                    std::cout << "Мониторинг запущен на интерфейсе: " << qPrintable(adapterName) << "\n";
                    isMonitoring = true;
                } else {
                    std::cout << "Ошибка запуска мониторинга: " << qPrintable(errorMessage) << "\n";
                    delete packetHandler;
                    packetHandler = nullptr;
                }
                break;
            }
            
            case 2: {
                if (!isMonitoring) {
                    std::cout << "Мониторинг не запущен!\n";
                    break;
                }
                
                if (packetHandler) {
                    packetHandler->stopCapture();
                    delete packetHandler;
                    packetHandler = nullptr;
                    isMonitoring = false;
                    std::cout << "Мониторинг остановлен\n";
                }
                break;
            }
            
            case 3: {
                std::cout << "Введите новый пароль для шифрования: ";
                g_encryptionPassword = QString::fromStdString(readPassword());
                std::cout << "Пароль успешно изменен\n";
                break;
            }
            
            case 4:
                if (packetHandler) {
                    packetHandler->stopCapture();
                    delete packetHandler;
                }
                return 0;
                
            default:
                std::cout << "Неверный выбор. Попробуйте снова.\n";
        }
    }
    
    return 0;
}
