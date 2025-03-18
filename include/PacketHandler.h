#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <string>
#include <pcap.h>
#include <QObject>
#include <QString>
#include <QThread>
#include <atomic>
#include <vector>
#include <QCryptographicHash>
#include <QByteArray>
#include <QMutex>
#include <QMap>

// Класс для шифрования и дешифрования данных (упрощенная реализация)
class LogEncryption {
public:
    // Генерация ключа на основе пароля
    static QByteArray generateKey(const QString& password) {
        return QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256);
    }
    
    // Шифрование данных
    static QByteArray encrypt(const QByteArray& data, const QByteArray& key) {
        QByteArray encrypted;
        encrypted.append(QCryptographicHash::hash(key, QCryptographicHash::Md5)); // IV
        
        QByteArray fullData = data;
        // Дополняем до блока 16 байт
        int padding = 16 - (fullData.size() % 16);
        for (int i = 0; i < padding; i++) {
            fullData.append(static_cast<char>(padding));
        }
        
        // Шифруем блоками XOR (упрощенная версия)
        QByteArray lastBlock = encrypted.left(16);
        for (int i = 0; i < fullData.size(); i += 16) {
            QByteArray block = fullData.mid(i, 16);
            QByteArray processed;
            
            // XOR с ключом и предыдущим блоком
            for (int j = 0; j < 16; j++) {
                processed.append(block[j] ^ key[j % key.size()] ^ lastBlock[j]);
            }
            
            encrypted.append(processed);
            lastBlock = processed;
        }
        
        return encrypted;
    }
    
    // Дешифрование данных
    static QByteArray decrypt(const QByteArray& encryptedData, const QByteArray& key) {
        if (encryptedData.size() <= 16) {
            return QByteArray(); // Слишком короткие данные
        }
        
        QByteArray iv = encryptedData.left(16);
        QByteArray data = encryptedData.mid(16);
        QByteArray decrypted;
        
        QByteArray lastBlock = iv;
        for (int i = 0; i < data.size(); i += 16) {
            QByteArray block = data.mid(i, 16);
            QByteArray processed;
            
            // XOR с ключом и предыдущим блоком
            for (int j = 0; j < block.size(); j++) {
                processed.append(block[j] ^ key[j % key.size()] ^ lastBlock[j]);
            }
            
            decrypted.append(processed);
            lastBlock = block;
        }
        
        // Удаляем padding
        if (!decrypted.isEmpty()) {
            int padding = static_cast<int>(decrypted.at(decrypted.size() - 1));
            if (padding > 0 && padding <= 16) {
                decrypted.chop(padding);
            }
        }
        
        return decrypted;
    }
};

class PacketHandler : public QObject {
    Q_OBJECT

public:
    explicit PacketHandler(QObject *parent = nullptr);
    ~PacketHandler();

    bool startCapture(const std::string& deviceName, QString* errorMessage = nullptr);
    void stopCapture();
    int getPacketCount() const { return packetCount; }
    
    void incrementPacketCount() { packetCount++; }
    
    // Методы для работы с шифрованными логами
    void setLogEncryptionEnabled(bool enabled, const QString& password = QString());
    bool isLogEncryptionEnabled() const { return encryptLogFile; }
    bool saveEncryptedLog(const QString& fileName, const QString& password);
    bool loadEncryptedLog(const QString& fileName, const QString& password);
    // Геттер для получения расшифрованных данных
    QByteArray getEncryptedLogData() const { return encryptedLogData; }

signals:
    void packetDetected(const QString& sourceIP, const QString& destinationIP, 
                       const QString& packetType, const QString& timestamp,
                       bool isPotentialThreat = false);

private:
    static void processPacket(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void logEvent(const std::string& message);
    std::vector<std::string> getLocalIPAddresses();
    
    pcap_t* handle;
    std::atomic<bool> isRunning;
    std::atomic<int> packetCount;
    QThread captureThread;
    std::vector<std::string> localIPAddresses;
    
    // Шифрование логов
    bool encryptLogFile;
    QByteArray encryptionKey;
    QByteArray encryptedLogData;
};

#endif // PACKET_HANDLER_H
