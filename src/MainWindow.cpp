#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QMessageBox>
#include <QDateTime>
#include <QStandardItemModel>
#include <QDebug>
#include <QGraphicsDropShadowEffect>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    packetHandler(new PacketHandler(this)),
    statusTimer(new QTimer(this)),
    isCapturing(false),
    totalPacketsDetected(0),
    isDarkMode(true) // По умолчанию используем темную тему
{
    ui->setupUi(this);
    
    // Настраиваем современный UI
    setupModernUI();
    
    // Настраиваем модель для таблицы подозрительных IP
    suspiciousIPModel = new SuspiciousIPModel(this);
    ui->tableViewSuspiciousIP->setModel(suspiciousIPModel);
    
    // Настраиваем таймер для обновления статусной строки
    statusTimer->setInterval(1000); // 1 секунда
    connect(statusTimer, &QTimer::timeout, this, &MainWindow::updateStatusBar);
    
    // Получаем список доступных устройств
    deviceNames = deviceManager.getDeviceList();
    for (const auto& device : deviceNames) {
        ui->comboBoxDevices->addItem(device);
    }
    
    // Подключаем сигналы и слоты
    connect(ui->pushButtonStart, &QPushButton::clicked, this, &MainWindow::onStartCapture);
    connect(ui->pushButtonStop, &QPushButton::clicked, this, &MainWindow::onStopCapture);
    connect(ui->comboBoxDevices, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::onDeviceSelected);
    connect(ui->pushButtonClear, &QPushButton::clicked, suspiciousIPModel, &SuspiciousIPModel::clearRecords);
    
    // Подключаем сигнал обнаружения пакета
    connect(packetHandler, &PacketHandler::packetDetected, this, &MainWindow::onPacketDetected);
    
    // Начальное состояние UI
    ui->pushButtonStop->setEnabled(false);
    ui->statusBar->showMessage("Готов к запуску");
    
    // Устанавливаем заголовок окна
    setWindowTitle("Система обнаружения вторжений (IDS)");
    
    // Настраиваем индикатор статуса
    setupStatusIndicator();
    updateStatusIndicator(false);
}

MainWindow::~MainWindow()
{
    if (isCapturing) {
        packetHandler->stopCapture();
    }
    delete ui;
}

void MainWindow::onStartCapture()
{
    if (ui->comboBoxDevices->currentIndex() < 0) {
        QMessageBox::warning(this, "Ошибка", "Пожалуйста, выберите сетевой интерфейс");
        return;
    }
    
    // Получаем имя устройства по индексу
    std::string deviceName = deviceManager.getDeviceNameByIndex(ui->comboBoxDevices->currentIndex());
    
    if (deviceName.empty()) {
        QMessageBox::critical(this, "Ошибка", "Не удалось получить имя устройства");
        return;
    }
    
    if (packetHandler->startCapture(deviceName)) {
        isCapturing = true;
        ui->pushButtonStart->setEnabled(false);
        ui->pushButtonStop->setEnabled(true);
        ui->comboBoxDevices->setEnabled(false);
        statusTimer->start();
        ui->statusBar->showMessage("Захват пакетов запущен...");
        updateStatusIndicator(true);
    } else {
        QMessageBox::critical(this, "Ошибка", "Не удалось запустить захват пакетов");
    }
}

void MainWindow::onStopCapture()
{
    packetHandler->stopCapture();
    isCapturing = false;
    ui->pushButtonStart->setEnabled(true);
    ui->pushButtonStop->setEnabled(false);
    ui->comboBoxDevices->setEnabled(true);
    statusTimer->stop();
    ui->statusBar->showMessage("Захват пакетов остановлен");
    updateStatusIndicator(false);
}

void MainWindow::onDeviceSelected(int index)
{
    if (index >= 0) {
        ui->pushButtonStart->setEnabled(true);
    } else {
        ui->pushButtonStart->setEnabled(false);
    }
}

void MainWindow::updateStatusBar()
{
    if (isCapturing) {
        int count = packetHandler->getPacketCount();
        ui->statusBar->showMessage(QString("Захват пакетов запущен... Обнаружено пакетов: %1").arg(count));
    }
}

void MainWindow::onPacketDetected(const QString& sourceIP, const QString& destinationIP, const QString& packetType, const QString& timestamp)
{
    // Добавляем информацию в лог
    QString logMessage = QString("[%1] %2 пакет от %3 к %4")
                            .arg(timestamp)
                            .arg(packetType)
                            .arg(sourceIP)
                            .arg(destinationIP);
    
    // Добавляем HTML-форматирование для лучшего отображения
    QString formattedMessage;
    if (packetType.contains("FLOOD", Qt::CaseInsensitive)) {
        formattedMessage = QString("<span style='color:#FF6B6B;font-weight:bold;'>[%1] %2 от %3 к %4</span>")
                            .arg(timestamp)
                            .arg(packetType)
                            .arg(sourceIP)
                            .arg(destinationIP);
    } else {
        formattedMessage = QString("<span style='color:#F1F6F9;'>[%1] %2 пакет от %3 к %4</span>")
                            .arg(timestamp)
                            .arg(packetType)
                            .arg(sourceIP)
                            .arg(destinationIP);
    }
    
    ui->textEditLog->append(formattedMessage);
    
    // Добавляем информацию в модель подозрительных IP
    suspiciousIPModel->addSuspiciousIP(sourceIP, destinationIP, packetType, timestamp);
    
    // Увеличиваем счетчик
    totalPacketsDetected++;
}

void MainWindow::setupModernUI()
{
    // Устанавливаем минимальный размер окна
    setMinimumSize(900, 700);
    
    // Настраиваем таблицу
    ui->tableViewSuspiciousIP->setAlternatingRowColors(true);
    ui->tableViewSuspiciousIP->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableViewSuspiciousIP->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableViewSuspiciousIP->horizontalHeader()->setStretchLastSection(true);
    ui->tableViewSuspiciousIP->verticalHeader()->setVisible(false);
    ui->tableViewSuspiciousIP->setShowGrid(false);
    
    // Добавляем эффект тени для кнопок
    for (auto* button : {ui->pushButtonStart, ui->pushButtonStop, ui->pushButtonClear}) {
        QGraphicsDropShadowEffect* shadowEffect = new QGraphicsDropShadowEffect(this);
        shadowEffect->setBlurRadius(10);
        shadowEffect->setColor(QColor(0, 0, 0, 80));
        shadowEffect->setOffset(2, 2);
        button->setGraphicsEffect(shadowEffect);
    }
    
    // Настраиваем текстовое поле для лога
    ui->textEditLog->setReadOnly(true);
    ui->textEditLog->document()->setMaximumBlockCount(1000); // Ограничиваем количество строк
    
    // Применяем тему
    updateTheme(isDarkMode);
}

void MainWindow::updateTheme(bool isDarkMode)
{
    this->isDarkMode = isDarkMode;
    
    // Тема уже применяется через QSS, но здесь можно добавить дополнительные настройки
    if (isDarkMode) {
        // Дополнительные настройки для темной темы
    } else {
        // Дополнительные настройки для светлой темы
    }
}

void MainWindow::setupStatusIndicator()
{
    // Создаем индикатор статуса
    statusIndicator = new QWidget(this);
    statusIndicator->setFixedSize(16, 16);
    statusIndicator->setStyleSheet("background-color: #FF6B6B; border-radius: 8px;");
    
    // Добавляем индикатор в статусную строку
    ui->statusBar->addPermanentWidget(statusIndicator);
}

void MainWindow::updateStatusIndicator(bool isActive)
{
    if (isActive) {
        // Зеленый индикатор для активного состояния
        statusIndicator->setStyleSheet("background-color: #4CAF50; border-radius: 8px;");
    } else {
        // Красный индикатор для неактивного состояния
        statusIndicator->setStyleSheet("background-color: #FF6B6B; border-radius: 8px;");
    }
} 