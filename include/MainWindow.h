#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QStandardItemModel>
#include <QStringList>
#include "PacketHandler.h"
#include "DeviceManager.h"
#include "SuspiciousIPModel.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartCapture();
    void onStopCapture();
    void onDeviceSelected(int index);
    void updateStatusBar();
    void onPacketDetected(const QString& sourceIP, const QString& destinationIP, 
                         const QString& packetType, const QString& timestamp, 
                         bool isPotentialThreat = false);
    
    // Новые методы для улучшения визуального отображения
    void updateTheme(bool isDarkMode);
    void setupStatusIndicator();
    void updateStatusIndicator(bool isActive);
    
    // Метод для генерации тестового трафика
    void generateTestTraffic();

private:
    Ui::MainWindow *ui;
    DeviceManager *deviceManager;
    PacketHandler *packetHandler;
    QTimer *statusTimer;
    SuspiciousIPModel *suspiciousIPModel;
    bool isCapturing;
    int totalPacketsDetected;
    
    // Новые переменные для улучшения визуального отображения
    QWidget *statusIndicator;
    bool isDarkMode;
    
    // Счетчики пакетов
    int suspiciousPacketsCount = 0;
    
    // Таймер для генерации тестового трафика
    QTimer *testTrafficTimer;

    void setupModernUI();
    void setupConnections();
    void addSuspiciousIP(const QString& sourceIP, const QString& destinationIP, 
                        const QString& packetType, const QString& timestamp);
};

#endif // MAINWINDOW_H 