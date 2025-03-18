#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTimer>
#include <QStandardItemModel>
#include <QStringList>
#include <QCloseEvent>
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

protected:
    // Переопределяем метод обработки события закрытия окна
    void closeEvent(QCloseEvent *event) override;

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
    
    // Методы для работы с шифрованием логов
    void onEncryptionToggled(bool checked);
    void onSaveEncryptedLog();
    void onLoadEncryptedLog();
    void showPasswordDialog(bool forSaving);
    
    // Метод для отображения диалога "О программе"
    void showAboutDialog();

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
    
    // Для шифрования логов
    QString lastEncryptionPassword;
    
    // Флаг сохранения логов - чтобы не спрашивать дважды
    bool logsSaved = false;

    void setupModernUI();
    void setupConnections();
    void setupMenus();
    void addSuspiciousIP(const QString& sourceIP, const QString& destinationIP, 
                         const QString& packetType, const QString& timestamp);
    
    // Новые методы для работы с логами
    void loadLogFile(const QString& filePath, const QString& password);
    void processLogLine(const QString& line);
    bool maybeSaveLog();  // Метод для предложения сохранить логи
    
    // Метод для сохранения логов
    bool saveLogsToFile(const QString& fileName, bool encrypted);
};

#endif // MAINWINDOW_H 