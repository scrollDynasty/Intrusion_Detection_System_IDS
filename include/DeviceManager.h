#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <string>
#include <QStringList>
#include <QMap>

class DeviceManager {
public:
    std::string chooseDevice();
    QStringList getDeviceList();
    
    // Новый метод для получения имени устройства по индексу
    std::string getDeviceNameByIndex(int index) const;
    
private:
    // Карта для хранения имен устройств (ключ - индекс, значение - имя устройства)
    QMap<int, std::string> deviceNamesMap;
};

#endif // DEVICE_MANAGER_H
