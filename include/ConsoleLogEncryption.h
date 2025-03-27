#ifndef CONSOLE_LOG_ENCRYPTION_H
#define CONSOLE_LOG_ENCRYPTION_H

#include <string>
#include <vector>
#include <array>
#include <openssl/evp.h>

/**
 * @brief Класс для шифрования и дешифрования логов без Qt-зависимостей
 * 
 * Реализует тот же алгоритм, что и в GUI-версии, чтобы логи были совместимы
 */
class ConsoleLogEncryption {
public:
    /**
     * @brief Генерация ключа на основе пароля (SHA-256)
     * @param password Пароль для генерации ключа
     * @return 32-байтный ключ
     */
    static std::vector<unsigned char> generateKey(const std::string& password) {
        std::vector<unsigned char> key(32); // SHA-256 = 32 bytes
        
        // Создаем контекст хеширования
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            return key; // Пустой ключ в случае ошибки
        }
        
        // Инициализируем хеширование SHA-256
        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(mdctx);
            return key;
        }
        
        // Обновляем контекст данными пароля
        if (EVP_DigestUpdate(mdctx, password.c_str(), password.length()) != 1) {
            EVP_MD_CTX_free(mdctx);
            return key;
        }
        
        // Получаем итоговый хеш
        unsigned int md_len = 0;
        if (EVP_DigestFinal_ex(mdctx, key.data(), &md_len) != 1) {
            EVP_MD_CTX_free(mdctx);
            return key;
        }
        
        // Освобождаем ресурсы
        EVP_MD_CTX_free(mdctx);
        return key;
    }
    
    /**
     * @brief Создание вектора инициализации (IV) из ключа с помощью MD5
     * @param key Ключ шифрования
     * @return 16-байтный IV
     */
    static std::vector<unsigned char> createIV(const std::vector<unsigned char>& key) {
        std::vector<unsigned char> iv(16); // MD5 = 16 bytes
        
        // Создаем контекст хеширования
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            return iv; // Пустой IV в случае ошибки
        }
        
        // Инициализируем хеширование MD5
        if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
            EVP_MD_CTX_free(mdctx);
            return iv;
        }
        
        // Обновляем контекст данными ключа
        if (EVP_DigestUpdate(mdctx, key.data(), key.size()) != 1) {
            EVP_MD_CTX_free(mdctx);
            return iv;
        }
        
        // Получаем итоговый хеш
        unsigned int md_len = 0;
        if (EVP_DigestFinal_ex(mdctx, iv.data(), &md_len) != 1) {
            EVP_MD_CTX_free(mdctx);
            return iv;
        }
        
        // Освобождаем ресурсы
        EVP_MD_CTX_free(mdctx);
        return iv;
    }
    
    /**
     * @brief Шифрование данных
     * @param data Данные для шифрования
     * @param key Ключ шифрования (32 байта)
     * @return Зашифрованные данные
     */
    static std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
        // Создаем вектор инициализации (IV) как MD5 от ключа
        std::vector<unsigned char> iv = createIV(key);
        
        // Копируем данные и добавляем padding
        std::vector<unsigned char> fullData = data;
        
        // Дополняем до блока 16 байт
        int padding = 16 - (fullData.size() % 16);
        for (int i = 0; i < padding; i++) {
            fullData.push_back(static_cast<unsigned char>(padding));
        }
        
        // Инициализируем результат с IV
        std::vector<unsigned char> encrypted = iv;
        
        // Шифруем блоками XOR (упрощенная версия, идентичная Qt-версии)
        std::vector<unsigned char> lastBlock = iv;
        
        for (size_t i = 0; i < fullData.size(); i += 16) {
            std::vector<unsigned char> block;
            
            // Копируем блок данных (не более 16 байт)
            for (size_t j = i; j < i + 16 && j < fullData.size(); j++) {
                block.push_back(fullData[j]);
            }
            
            // Если блок неполный, дополняем его до 16 байт
            while (block.size() < 16) {
                block.push_back(0);
            }
            
            std::vector<unsigned char> processed(16);
            
            // XOR с ключом и предыдущим блоком
            for (int j = 0; j < 16; j++) {
                processed[j] = block[j] ^ key[j % key.size()] ^ lastBlock[j];
            }
            
            // Добавляем зашифрованный блок к результату
            encrypted.insert(encrypted.end(), processed.begin(), processed.end());
            lastBlock = processed;
        }
        
        return encrypted;
    }
    
    /**
     * @brief Дешифрование данных
     * @param encryptedData Зашифрованные данные
     * @param key Ключ шифрования (32 байта)
     * @return Расшифрованные данные
     */
    static std::vector<unsigned char> decrypt(const std::vector<unsigned char>& encryptedData, const std::vector<unsigned char>& key) {
        if (encryptedData.size() <= 16) {
            return std::vector<unsigned char>(); // Слишком короткие данные
        }
        
        // Извлекаем IV (первые 16 байт)
        std::vector<unsigned char> iv(encryptedData.begin(), encryptedData.begin() + 16);
        
        // Извлекаем зашифрованные данные (все, кроме IV)
        std::vector<unsigned char> data(encryptedData.begin() + 16, encryptedData.end());
        
        std::vector<unsigned char> decrypted;
        
        // Дешифруем блоками
        std::vector<unsigned char> lastBlock = iv;
        
        for (size_t i = 0; i < data.size(); i += 16) {
            std::vector<unsigned char> block;
            
            // Копируем блок данных (не более 16 байт)
            for (size_t j = i; j < i + 16 && j < data.size(); j++) {
                block.push_back(data[j]);
            }
            
            // Если блок неполный, дополняем его до 16 байт
            while (block.size() < 16) {
                block.push_back(0);
            }
            
            std::vector<unsigned char> processed(16);
            
            // XOR с ключом и предыдущим блоком
            for (int j = 0; j < 16; j++) {
                processed[j] = block[j] ^ key[j % key.size()] ^ lastBlock[j];
            }
            
            // Добавляем расшифрованный блок к результату
            decrypted.insert(decrypted.end(), processed.begin(), processed.end());
            lastBlock = block;
        }
        
        // Удаляем padding
        if (!decrypted.empty()) {
            int padding = static_cast<int>(decrypted.back());
            if (padding > 0 && padding <= 16) {
                decrypted.resize(decrypted.size() - padding);
            }
        }
        
        return decrypted;
    }
    
    /**
     * @brief Конвертация строки в вектор байт
     * @param str Исходная строка
     * @return Вектор байт
     */
    static std::vector<unsigned char> stringToBytes(const std::string& str) {
        return std::vector<unsigned char>(str.begin(), str.end());
    }
    
    /**
     * @brief Конвертация вектора байт в строку
     * @param bytes Исходный вектор байт
     * @return Строка
     */
    static std::string bytesToString(const std::vector<unsigned char>& bytes) {
        return std::string(bytes.begin(), bytes.end());
    }
};

#endif // CONSOLE_LOG_ENCRYPTION_H 