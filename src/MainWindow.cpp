#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QMessageBox>
#include <QDateTime>
#include <QStandardItemModel>
#include <QDebug>
#include <QGraphicsDropShadowEffect>
#include <QRandomGenerator>
#include <QScrollBar>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow),
    packetHandler(new PacketHandler(this)),
    statusTimer(new QTimer(this)),
    isCapturing(false),
    totalPacketsDetected(0),
    isDarkMode(true), // По умолчанию используем темную тему
    testTrafficTimer(new QTimer(this)),
    suspiciousIPModel(new SuspiciousIPModel(this)),
    deviceManager(new DeviceManager(this))
{
    ui->setupUi(this);
    
    // Настраиваем современный UI
    setupModernUI();
    
    // Настраиваем модель для таблицы подозрительных IP
    ui->tableViewSuspiciousIP->setModel(suspiciousIPModel);
    
    // Настраиваем таймер для обновления статусной строки
    statusTimer->setInterval(1000); // 1 секунда
    connect(statusTimer, &QTimer::timeout, this, &MainWindow::updateStatusBar);
    
    // Получаем список доступных устройств
    auto deviceList = deviceManager->getDeviceList();
    for (const auto& device : deviceList) {
        ui->comboBoxDevices->addItem(QString::fromStdString(device));
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
    setWindowTitle("Система обнаружения вторжений");
    
    // Настраиваем индикатор статуса
    setupStatusIndicator();
    updateStatusIndicator(false);
    
    // Добавляем кнопку для генерации тестового трафика в основной интерфейс
    QPushButton* testTrafficButton = new QPushButton("Тестовый трафик", this);
    ui->verticalLayout->addWidget(testTrafficButton);
    connect(testTrafficButton, &QPushButton::clicked, this, &MainWindow::generateTestTraffic);
    
    // Настраиваем таймер для генерации тестового трафика
    testTrafficTimer->setInterval(1000); // 1 секунда между пакетами
    connect(testTrafficTimer, &QTimer::timeout, this, &MainWindow::generateTestTraffic);
    
    // Выводим информацию о запуске
    ui->textEditLog->append("<span style='color:#4CAF50;'>Система обнаружения вторжений запущена</span>");
    ui->textEditLog->append("<span style='color:#4CAF50;'>Выберите сетевой адаптер и нажмите 'Старт' для начала захвата пакетов</span>");
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
    std::string deviceName = deviceManager->getDeviceNameByIndex(ui->comboBoxDevices->currentIndex());
    
    if (deviceName.empty()) {
        QMessageBox::critical(this, "Ошибка", "Не удалось получить имя устройства");
        return;
    }
    
    qDebug() << "Выбранное устройство:" << QString::fromStdString(deviceName);
    
    // Проверяем, выбран ли тестовый адаптер
    if (deviceName == "test0") {
        // Запускаем генерацию тестового трафика
        isCapturing = true;
        ui->pushButtonStart->setEnabled(false);
        ui->pushButtonStop->setEnabled(true);
        ui->comboBoxDevices->setEnabled(false);
        statusTimer->start();
        ui->statusBar->showMessage("Тестовый режим активирован...");
        updateStatusIndicator(true);
        
        // Запускаем таймер для генерации тестового трафика
        testTrafficTimer->start();
        
        // Генерируем первый тестовый пакет сразу
        generateTestTraffic();
        
        return;
    }
    
    // Предупреждаем пользователя о необходимости прав администратора
    QMessageBox::information(this, "Информация", 
                           "Для захвата реальных пакетов рекомендуется запустить программу от имени администратора.\n\n"
                           "Если программа закроется после нажатия OK, перезапустите ее от имени администратора.");
    
    // Пробуем запустить захват пакетов
    QString errorMessage;
    if (packetHandler->startCapture(deviceName, &errorMessage)) {
        isCapturing = true;
        ui->pushButtonStart->setEnabled(false);
        ui->pushButtonStop->setEnabled(true);
        ui->comboBoxDevices->setEnabled(false);
        statusTimer->start();
        ui->statusBar->showMessage("Захват пакетов запущен...");
        updateStatusIndicator(true);
    } else {
        // Показываем подробное сообщение об ошибке
        QString detailedError = "Не удалось запустить захват пакетов.\n\n";
        
        if (!errorMessage.isEmpty()) {
            detailedError += errorMessage + "\n\n";
        }
        
        detailedError += "Возможные причины:\n";
        detailedError += "1. Npcap не установлен или установлен неправильно\n";
        detailedError += "2. У приложения недостаточно прав (запустите от имени администратора)\n";
        detailedError += "3. Выбранный сетевой адаптер недоступен или не поддерживается\n";
        detailedError += "4. Другое приложение уже использует этот адаптер\n\n";
        detailedError += "Рекомендации:\n";
        detailedError += "- Установите Npcap с официального сайта: https://nmap.org/npcap/\n";
        detailedError += "- При установке выберите опцию 'Install Npcap in WinPcap API-compatible Mode'\n";
        detailedError += "- Перезагрузите компьютер после установки Npcap\n";
        detailedError += "- Запустите приложение от имени администратора";
        
        QMessageBox msgBox;
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.setWindowTitle("Ошибка");
        msgBox.setText("Не удалось запустить захват пакетов");
        msgBox.setDetailedText(detailedError);
        msgBox.setStandardButtons(QMessageBox::Ok);
        msgBox.exec();
    }
}

void MainWindow::onStopCapture()
{
    if (testTrafficTimer->isActive()) {
        // Останавливаем генерацию тестового трафика
        testTrafficTimer->stop();
    } else {
        packetHandler->stopCapture();
    }
    
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
        ui->statusBar->showMessage(QString("Захват пакетов запущен... Обнаружено пакетов: %1 | Подозрительных: %2")
                                  .arg(count)
                                  .arg(suspiciousPacketsCount));
    }
}

void MainWindow::onPacketDetected(const QString& sourceIP, const QString& destinationIP, 
                                 const QString& packetType, const QString& timestamp,
                                 bool isPotentialThreat) {
    // Обновляем счетчик пакетов
    int packetCount = packetHandler->getPacketCount();
    // Обновляем счетчик в статусной строке
    updateStatusBar();
    
    // Форматируем сообщение для лога
    QString logMessage;
    
    if (isPotentialThreat) {
        // Выделяем подозрительные пакеты красным цветом
        logMessage = QString("<span style='color:red;'>[%1] %2 → %3: %4 (ПОДОЗРИТЕЛЬНЫЙ)</span>")
                    .arg(timestamp)
                    .arg(sourceIP)
                    .arg(destinationIP)
                    .arg(packetType);
        
        // Добавляем IP в список подозрительных
        addSuspiciousIP(sourceIP, destinationIP, packetType, timestamp);
    } else {
        // Обычные пакеты отображаем обычным цветом
        logMessage = QString("[%1] %2 → %3: %4")
                    .arg(timestamp)
                    .arg(sourceIP)
                    .arg(destinationIP)
                    .arg(packetType);
    }
    
    // Добавляем сообщение в лог
    ui->textEditLog->append(logMessage);
    
    // Прокручиваем лог вниз
    QScrollBar *scrollBar = ui->textEditLog->verticalScrollBar();
    scrollBar->setValue(scrollBar->maximum());
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
    
    // Настраиваем автоматическое изменение размера столбцов таблицы
    ui->tableViewSuspiciousIP->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    
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
    ui->textEditLog->setLineWrapMode(QTextEdit::WidgetWidth); // Автоматический перенос текста
    ui->textEditLog->setWordWrapMode(QTextOption::WrapAtWordBoundaryOrAnywhere); // Перенос по словам или символам
    
    // Настраиваем сплиттер для автоматического изменения размера
    ui->splitter->setStretchFactor(0, 1); // Таблица
    ui->splitter->setStretchFactor(1, 1); // Лог
    
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

void MainWindow::generateTestTraffic() {
    // Генерируем случайные IP-адреса
    QString sourceIP = QString("%1.%2.%3.%4")
                      .arg(QRandomGenerator::global()->bounded(1, 255))
                      .arg(QRandomGenerator::global()->bounded(0, 255))
                      .arg(QRandomGenerator::global()->bounded(0, 255))
                      .arg(QRandomGenerator::global()->bounded(1, 255));
    
    QString destinationIP = QString("%1.%2.%3.%4")
                           .arg(QRandomGenerator::global()->bounded(1, 255))
                           .arg(QRandomGenerator::global()->bounded(0, 255))
                           .arg(QRandomGenerator::global()->bounded(0, 255))
                           .arg(QRandomGenerator::global()->bounded(1, 255));
    
    // Генерируем случайный тип пакета (TCP, UDP, ICMP)
    int packetTypeIndex = QRandomGenerator::global()->bounded(0, 3);
    QString packetType;
    QString details;
    bool isPotentialThreat = false;
    
    // Генерируем случайные порты
    int sourcePort = QRandomGenerator::global()->bounded(1024, 65535);
    int destPort = QRandomGenerator::global()->bounded(1, 65535);
    
    // Определяем тип пакета и детали
    switch (packetTypeIndex) {
        case 0: { // TCP
            // Генерируем случайный TCP флаг (SYN, ACK, FIN, RST)
            int tcpFlagIndex = QRandomGenerator::global()->bounded(0, 5);
            
            switch (tcpFlagIndex) {
                case 0: // SYN
                    packetType = "TCP SYN";
                    
                    // Если порт назначения < 1024, это может быть сканирование портов
                    if (destPort < 1024) {
                        details = QString(" (Порт %1 → %2) Возможное сканирование портов")
                                 .arg(sourcePort)
                                 .arg(destPort);
                        
                        // С вероятностью 70% помечаем как потенциальную угрозу
                        isPotentialThreat = (QRandomGenerator::global()->bounded(0, 100) < 70);
                    } else {
                        details = QString(" (Порт %1 → %2)")
                                 .arg(sourcePort)
                                 .arg(destPort);
                    }
                    
                    // Проверка на известные уязвимые порты
                    if (destPort == 445 || destPort == 135 || destPort == 139 || // SMB/NetBIOS
                        destPort == 3389 || // RDP
                        destPort == 22 || // SSH
                        destPort == 23 || // Telnet
                        destPort == 1433 || destPort == 1434 || // MS SQL
                        destPort == 3306) { // MySQL
                        
                        details += " (Попытка подключения к потенциально уязвимому сервису)";
                        isPotentialThreat = true;
                    }
                    break;
                    
                case 1: // SYN-ACK
                    packetType = "TCP SYN-ACK";
                    details = QString(" (Порт %1 → %2) Установка соединения")
                             .arg(sourcePort)
                             .arg(destPort);
                    break;
                    
                case 2: // FIN
                    packetType = "TCP FIN";
                    details = QString(" (Порт %1 → %2) Завершение соединения")
                             .arg(sourcePort)
                             .arg(destPort);
                    break;
                    
                case 3: // RST
                    packetType = "TCP RST";
                    details = QString(" (Порт %1 → %2) Сброс соединения")
                             .arg(sourcePort)
                             .arg(destPort);
                    
                    // С вероятностью 30% помечаем как потенциальную угрозу
                    isPotentialThreat = (QRandomGenerator::global()->bounded(0, 100) < 30);
                    break;
                    
                case 4: // ACK
                    packetType = "TCP ACK";
                    details = QString(" (Порт %1 → %2) Подтверждение")
                             .arg(sourcePort)
                             .arg(destPort);
                    break;
            }
            break;
        }
        
        case 1: { // UDP
            packetType = "UDP";
            details = QString(" (Порт %1 → %2)")
                     .arg(sourcePort)
                     .arg(destPort);
            
            // Проверка на известные уязвимые UDP порты
            if (destPort == 53 || // DNS
                destPort == 161 || destPort == 162 || // SNMP
                destPort == 1900 || // UPnP
                destPort == 5353) { // mDNS
                
                // С вероятностью 20% помечаем как потенциальную угрозу (UDP флуд)
                if (QRandomGenerator::global()->bounded(0, 100) < 20) {
                    details += " (Возможный UDP флуд)";
                    isPotentialThreat = true;
                }
            }
            break;
        }
        
        case 2: { // ICMP
            packetType = "ICMP";
            details = " (ping)";
            
            // С вероятностью 10% помечаем как потенциальную угрозу (ping flood)
            if (QRandomGenerator::global()->bounded(0, 100) < 10) {
                details += " (Возможный ping flood)";
                isPotentialThreat = true;
            }
            break;
        }
    }
    
    // Получаем текущее время
    QDateTime now = QDateTime::currentDateTime();
    QString timestamp = now.toString("yyyy-MM-dd hh:mm:ss");
    
    // Отправляем сигнал с информацией о пакете
    onPacketDetected(sourceIP, destinationIP, packetType + details, timestamp, isPotentialThreat);
    
    // Увеличиваем счетчик пакетов
    packetHandler->incrementPacketCount();
}

void MainWindow::addSuspiciousIP(const QString& sourceIP, const QString& destinationIP, 
                                const QString& packetType, const QString& timestamp) {
    // Добавляем IP в модель подозрительных IP
    suspiciousIPModel->addSuspiciousIP(sourceIP, destinationIP, packetType, timestamp);
    
    // Обновляем счетчик подозрительных пакетов
    suspiciousPacketsCount++;
    // Обновляем информацию в статусной строке
    updateStatusBar();
} 