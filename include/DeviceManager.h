#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <QObject>

class DeviceManager : public QObject {
    Q_OBJECT

public:
    explicit DeviceManager(QObject *parent = nullptr);
    ~DeviceManager();

    std::vector<std::string> getDeviceList();
    std::string getDeviceNameByIndex(int index);

private:
    std::vector<std::string> deviceList;
    std::map<int, std::string> deviceNamesMap;
};

#endif // DEVICE_MANAGER_H
