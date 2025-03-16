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
    void onPacketDetected(const QString& sourceIP, const QString& destinationIP, const QString& packetType, const QString& timestamp);
    
    // Новые методы для улучшения визуального отображения
    void setupModernUI();
    void updateTheme(bool isDarkMode);
    void setupStatusIndicator();
    void updateStatusIndicator(bool isActive);

private:
    Ui::MainWindow *ui;
    DeviceManager deviceManager;
    PacketHandler *packetHandler;
    QTimer *statusTimer;
    SuspiciousIPModel *suspiciousIPModel;
    QStringList deviceNames;
    bool isCapturing;
    int totalPacketsDetected;
    
    // Новые переменные для улучшения визуального отображения
    QWidget *statusIndicator;
    bool isDarkMode;
};

#endif // MAINWINDOW_H 