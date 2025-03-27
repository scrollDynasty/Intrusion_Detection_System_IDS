#include "MainWindow.h"
#include "ui_MainWindow.h"
#include <QMessageBox>
#include <QDateTime>
#include <QStandardItemModel>
#include <QDebug>
#include <QGraphicsDropShadowEffect>
#include <QRandomGenerator>
#include <QScrollBar>
#include <QSpacerItem>
#include <QGridLayout>
#include <QSizePolicy>
#include <QInputDialog>
#include <QFileDialog>
#include <QProgressDialog>
#include <QRegularExpression>
#include <QCloseEvent>
#include <QThread>
#include <QApplication>
#include "PacketHandler.h"
#include "DeviceManager.h"
#include "SuspiciousIPModel.h"

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
    
    // Явно включаем тултипы
    ui->tableViewSuspiciousIP->setMouseTracking(true);
    ui->tableViewSuspiciousIP->viewport()->setMouseTracking(true);
    ui->tableViewSuspiciousIP->setAttribute(Qt::WA_AlwaysShowToolTips, true);
    
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
    testTrafficTimer->setInterval(2000); // Каждые 2 секунды
    connect(testTrafficTimer, &QTimer::timeout, this, &MainWindow::generateTestTraffic);
    
    // Создаем все меню приложения
    setupMenus();
    
    // После завершения всех настроек отображаем сообщение о готовности
    ui->statusBar->showMessage("Система готова к работе");
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
    
    // Предупреждаем пользователя о необходимости прав администратора и правильного сетевого адаптера
    QMessageBox msgInfo;
    msgInfo.setWindowTitle("Информация");
    msgInfo.setIcon(QMessageBox::Information);
    msgInfo.setText("Для захвата всех пакетов в сети необходимо:\n\n"
                   "1. Запустить программу от имени администратора\n"
                   "2. Выбрать правильный сетевой адаптер (физический, а не виртуальный)\n"
                   "3. Убедиться, что сетевой адаптер поддерживает режим promiscuous\n\n"
                   "Это позволит обнаруживать сканирование портов и другие атаки с других компьютеров в сети.\n\n"
                   "Если программа закроется после нажатия OK, перезапустите ее от имени администратора.");
    msgInfo.setStandardButtons(QMessageBox::Ok);
    msgInfo.exec();
    
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
        
        // Добавляем информацию о режиме захвата
        ui->textEditLog->append("<span style='color:#4CAF50;'>Захват пакетов запущен в режиме promiscuous. Система будет обнаруживать сканирование портов и другие атаки с других компьютеров в сети.</span>");
        ui->textEditLog->append("<span style='color:#4CAF50;'>Если вы не видите пакеты с других компьютеров, проверьте, что выбран правильный сетевой адаптер и он поддерживает режим promiscuous.</span>");
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
        detailedError += "4. Другое приложение уже использует этот адаптер\n";
        detailedError += "5. Сетевой адаптер не поддерживает режим promiscuous\n\n";
        detailedError += "Рекомендации:\n";
        detailedError += "- Установите Npcap с официального сайта: https://nmap.org/npcap/\n";
        detailedError += "- При установке выберите опцию 'Install Npcap in WinPcap API-compatible Mode'\n";
        detailedError += "- Перезагрузите компьютер после установки Npcap\n";
        detailedError += "- Запустите приложение от имени администратора\n";
        detailedError += "- Выберите физический сетевой адаптер, а не виртуальный\n";
        detailedError += "- Проверьте, что сетевой адаптер поддерживает режим promiscuous";
        
        QMessageBox msgBox;
        msgBox.setIcon(QMessageBox::Critical);
        msgBox.setWindowTitle("Ошибка");
        msgBox.setText("Не удалось запустить захват пакетов");
        msgBox.setDetailedText(detailedError);
        msgBox.setStandardButtons(QMessageBox::Ok);
        
        // Устанавливаем кодировку для корректного отображения текста на всех компьютерах
        QFont font = msgBox.font();
        msgBox.setFont(font);
        
        // Увеличиваем размер окна для лучшей читаемости
        QSpacerItem* horizontalSpacer = new QSpacerItem(500, 0, QSizePolicy::Minimum, QSizePolicy::Expanding);
        QGridLayout* layout = (QGridLayout*)msgBox.layout();
        layout->addItem(horizontalSpacer, layout->rowCount(), 0, 1, layout->columnCount());
        
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
        // Выделяем подозрительные пакеты красным цветом и жирным шрифтом
        logMessage = QString("<span style='color:#FF0000; font-weight:bold;'>[%1] %2 → %3: %4 (ПОДОЗРИТЕЛЬНЫЙ)</span>")
                    .arg(timestamp)
                    .arg(sourceIP)
                    .arg(destinationIP)
                    .arg(packetType);
        
        // Добавляем IP в список подозрительных
        addSuspiciousIP(sourceIP, destinationIP, packetType, timestamp);
        
        // Генерируем отдельное уведомление об атаке с красным цветом и выделенным фоном
        QString alertMessage = QString("<span style='color:#FF0000; font-weight:bold; background-color:#FFEEEE;'>ПРЕДУПРЕЖДЕНИЕ: Обнаружена попытка атаки с %1 на %2 (%3)</span>")
                          .arg(sourceIP)
                          .arg(destinationIP)
                          .arg(packetType);
        ui->textEditLog->append(alertMessage);
        
        // Принудительно прокручиваем список подозрительных IP вниз, чтобы увидеть новую запись
        ui->tableViewSuspiciousIP->scrollToBottom();
        
        // Выделяем новую запись в таблице для привлечения внимания
        int row = suspiciousIPModel->rowCount() - 1;
        if (row >= 0) {
            QModelIndex index = suspiciousIPModel->index(row, 0);
            ui->tableViewSuspiciousIP->selectionModel()->select(
                index, 
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows
            );
            ui->tableViewSuspiciousIP->setFocus();
        }
    } else {
        // Обычные пакеты отображаем нормальным цветом (без выделения)
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
    
    // Увеличиваем размер шрифта в таблице для лучшей видимости
    QFont tableFont = ui->tableViewSuspiciousIP->font();
    tableFont.setPointSize(10);
    ui->tableViewSuspiciousIP->setFont(tableFont);
    
    // Улучшаем отображение заголовков таблицы
    QHeaderView* header = ui->tableViewSuspiciousIP->horizontalHeader();
    header->setHighlightSections(false);
    header->setSectionResizeMode(QHeaderView::Stretch);
    
    // Автоматическое изменение размера таблицы при добавлении новых данных
    ui->tableViewSuspiciousIP->resizeColumnsToContents();
    ui->tableViewSuspiciousIP->resizeRowsToContents();
    
    // Устанавливаем цвет фона для лога
    QPalette logPalette = ui->textEditLog->palette();
    logPalette.setColor(QPalette::Base, QColor(240, 240, 240)); // Светло-серый фон
    ui->textEditLog->setPalette(logPalette);
    
    // Увеличиваем размер шрифта в журнале
    QFont logFont = ui->textEditLog->font();
    logFont.setPointSize(10);
    ui->textEditLog->setFont(logFont);
    
    // Настраиваем отображение для темного режима
    updateTheme(isDarkMode);
}

void MainWindow::updateTheme(bool isDarkMode)
{
    this->isDarkMode = isDarkMode;
    
    // Устанавливаем стили для лучшей видимости контента
    if (isDarkMode) {
        // Цвета для темной темы
        QPalette darkPalette;
        darkPalette.setColor(QPalette::Window, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::WindowText, Qt::white);
        darkPalette.setColor(QPalette::Base, QColor(25, 25, 25));
        darkPalette.setColor(QPalette::AlternateBase, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
        darkPalette.setColor(QPalette::ToolTipText, Qt::white);
        darkPalette.setColor(QPalette::Text, Qt::white);
        darkPalette.setColor(QPalette::Button, QColor(53, 53, 53));
        darkPalette.setColor(QPalette::ButtonText, Qt::white);
        darkPalette.setColor(QPalette::BrightText, Qt::red);
        darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::Highlight, QColor(42, 130, 218));
        darkPalette.setColor(QPalette::HighlightedText, Qt::black);
        
        // Устанавливаем палитру для приложения
        qApp->setPalette(darkPalette);
        
        // Специфичные стили для виджетов
        ui->tableViewSuspiciousIP->setStyleSheet(
            "QTableView { background-color: #212121; color: #FFFFFF; gridline-color: #444444; }"
            "QHeaderView::section { background-color: #424242; color: #FFFFFF; padding: 4px; }"
        );
        
        // Устанавливаем стиль для текстового лога в темной теме
        ui->textEditLog->setStyleSheet(
            "QTextEdit { background-color: #212121; color: #D0D0D0; border: 1px solid #444444; }"
        );
    } else {
        // Цвета для светлой темы
        QPalette lightPalette;
        lightPalette.setColor(QPalette::Window, QColor(240, 240, 240));
        lightPalette.setColor(QPalette::WindowText, Qt::black);
        lightPalette.setColor(QPalette::Base, QColor(255, 255, 255));
        lightPalette.setColor(QPalette::AlternateBase, QColor(233, 233, 233));
        lightPalette.setColor(QPalette::ToolTipBase, Qt::white);
        lightPalette.setColor(QPalette::ToolTipText, Qt::black);
        lightPalette.setColor(QPalette::Text, Qt::black);
        lightPalette.setColor(QPalette::Button, QColor(240, 240, 240));
        lightPalette.setColor(QPalette::ButtonText, Qt::black);
        lightPalette.setColor(QPalette::BrightText, Qt::red);
        lightPalette.setColor(QPalette::Link, QColor(0, 0, 255));
        lightPalette.setColor(QPalette::Highlight, QColor(180, 200, 250));
        lightPalette.setColor(QPalette::HighlightedText, Qt::black);
        
        // Устанавливаем палитру для приложения
        qApp->setPalette(lightPalette);
        
        // Специфичные стили для виджетов
        ui->tableViewSuspiciousIP->setStyleSheet(
            "QTableView { background-color: #FFFFFF; color: #000000; gridline-color: #CCCCCC; }"
            "QHeaderView::section { background-color: #F0F0F0; color: #000000; padding: 4px; }"
        );
        
        // Устанавливаем стиль для текстового лога в светлой теме
        ui->textEditLog->setStyleSheet(
            "QTextEdit { background-color: #FFFFFF; color: #000000; border: 1px solid #CCCCCC; }"
        );
    }
    
    // Явно устанавливаем палитру для таблицы, чтобы тултипы работали
    if (isDarkMode) {
        QPalette tooltipPalette = ui->tableViewSuspiciousIP->palette();
        tooltipPalette.setColor(QPalette::ToolTipBase, QColor(53, 53, 53));
        tooltipPalette.setColor(QPalette::ToolTipText, Qt::white);
        ui->tableViewSuspiciousIP->setPalette(tooltipPalette);
    } else {
        QPalette tooltipPalette = ui->tableViewSuspiciousIP->palette();
        tooltipPalette.setColor(QPalette::ToolTipBase, Qt::white);
        tooltipPalette.setColor(QPalette::ToolTipText, Qt::black);
        ui->tableViewSuspiciousIP->setPalette(tooltipPalette);
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
    
    // Увеличиваем шанс генерации подозрительных пакетов для тестирования
    // Базовый шанс 40% для любого типа пакета
    bool forceSuspicious = (QRandomGenerator::global()->bounded(0, 100) < 40);
    
    // Определяем тип пакета и детали
    switch (packetTypeIndex) {
        case 0: { // TCP
            // Генерируем случайный TCP флаг (SYN, ACK, FIN, RST)
            int tcpFlagIndex = QRandomGenerator::global()->bounded(0, 5);
            
            if (forceSuspicious) {
                // Если нужен подозрительный пакет, выбираем SYN или RST с большей вероятностью
                tcpFlagIndex = QRandomGenerator::global()->bounded(0, 2) == 0 ? 0 : 3; // SYN или RST
                // И выбираем уязвимый порт
                destPort = QRandomGenerator::global()->bounded(1, 5) == 1 ? 3389 : // RDP
                          (QRandomGenerator::global()->bounded(1, 5) == 2 ? 22 :   // SSH
                          (QRandomGenerator::global()->bounded(1, 5) == 3 ? 1433 : // MS SQL
                          (QRandomGenerator::global()->bounded(1, 5) == 4 ? 3306 : 445))); // MySQL или SMB
            }
            
            switch (tcpFlagIndex) {
                case 0: // SYN
                    packetType = "TCP SYN";
                    
                    // Если порт назначения < 1024, это может быть сканирование портов
                    if (destPort < 1024 || forceSuspicious) {
                        details = QString(" (Порт %1 → %2) Возможное сканирование портов")
                                 .arg(sourcePort)
                                 .arg(destPort);
                        
                        // Повышаем шанс подозрительного пакета
                        isPotentialThreat = (QRandomGenerator::global()->bounded(0, 100) < 70) || forceSuspicious;
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
                    
                    // Повышаем шанс подозрительного пакета
                    isPotentialThreat = (QRandomGenerator::global()->bounded(0, 100) < 50) || forceSuspicious;
                    if (isPotentialThreat) {
                        details += " (Возможный сброс соединения)";
                    }
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
            
            if (forceSuspicious) {
                // Если нужен подозрительный пакет, выбираем уязвимый порт
                destPort = QRandomGenerator::global()->bounded(1, 4) == 1 ? 53 :  // DNS
                          (QRandomGenerator::global()->bounded(1, 4) == 2 ? 161 : // SNMP
                          (QRandomGenerator::global()->bounded(1, 4) == 3 ? 1900 : 5353)); // UPnP или mDNS
            }
            
            // Проверка на известные уязвимые UDP порты
            if (destPort == 53 || // DNS
                destPort == 161 || destPort == 162 || // SNMP
                destPort == 1900 || // UPnP
                destPort == 5353) { // mDNS
                
                // Повышаем шанс подозрительного пакета
                isPotentialThreat = (QRandomGenerator::global()->bounded(0, 100) < 60) || forceSuspicious;
                if (isPotentialThreat) {
                    details += " (Возможный UDP флуд)";
                }
            }
            break;
        }
        
        case 2: { // ICMP
            packetType = "ICMP";
            details = " (ping)";
            
            // Повышаем шанс подозрительного пакета
            isPotentialThreat = (QRandomGenerator::global()->bounded(0, 100) < 40) || forceSuspicious;
            if (isPotentialThreat) {
                details += " (Возможный ping flood)";
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
    
    // Обновляем таблицу - гарантируем, что новая запись будет видна
    ui->tableViewSuspiciousIP->resizeColumnsToContents();
    ui->tableViewSuspiciousIP->resizeRowsToContents();
    ui->tableViewSuspiciousIP->scrollToBottom(); // Прокручиваем к новой записи
    
    // Обновляем информацию в статусной строке
    updateStatusBar();
    
    // Выводим информационное сообщение в статусной строке
    ui->statusBar->showMessage(QString("Обнаружен подозрительный IP: %1 -> %2 (%3)").arg(sourceIP).arg(destinationIP).arg(packetType), 5000);
}

// Методы для работы с шифрованием логов
void MainWindow::onEncryptionToggled(bool checked) {
    if (checked) {
        // Запрашиваем пароль для шифрования
        showPasswordDialog(true);
    } else {
        // Сбрасываем пароль шифрования
        lastEncryptionPassword.clear();
        ui->statusBar->showMessage("Шифрование логов отключено", 3000);
    }
}

void MainWindow::showPasswordDialog(bool forSaving) {
    bool ok;
    QString password = QInputDialog::getText(
        this, 
        forSaving ? "Установка пароля шифрования" : "Ввод пароля шифрования", 
        forSaving ? "Введите пароль для шифрования логов:" : "Введите пароль для расшифровки:", 
        QLineEdit::Password, 
        "", 
        &ok
    );
    
    if (ok && !password.isEmpty()) {
        lastEncryptionPassword = password;
        
        if (forSaving) {
            // Для сохранения просто запоминаем пароль
            ui->statusBar->showMessage("Пароль шифрования установлен", 3000);
        } else {
            // Это для загрузки - показываем диалог выбора файла с правильным фильтром
            QString fileName = QFileDialog::getOpenFileName(
                this, 
                "Загрузить зашифрованный файл логов", 
                "", 
                "Зашифрованные логи (*.enc);;Все файлы (*)",
                nullptr,
                QFileDialog::ReadOnly
            );
            
            if (!fileName.isEmpty()) {
                // Загружаем логи с обновлением таблицы
                loadLogFile(fileName, password);
            }
        }
    } else if (ok && password.isEmpty()) {
        QMessageBox::warning(this, "Предупреждение", "Пароль не может быть пустым");
        if (forSaving) {
            // Отключаем чекбокс шифрования, если пароль пустой
            QAction* action = qobject_cast<QAction*>(sender());
            if (action) {
                action->setChecked(false);
            }
        }
    }
}

void MainWindow::onSaveEncryptedLog() {
    if (lastEncryptionPassword.isEmpty()) {
        // Если пароль ещё не установлен, запрашиваем его
        showPasswordDialog(true);
        if (lastEncryptionPassword.isEmpty()) {
            return; // Пользователь отменил операцию
        }
    }
    
    QString fileName = QFileDialog::getSaveFileName(
        this, 
        "Сохранить зашифрованный лог", 
        "logs.enc", 
        "Зашифрованные логи (*.enc);;Все файлы (*)"
    );
    
    if (!fileName.isEmpty()) {
        // Проверяем расширение
        if (!fileName.endsWith(".enc", Qt::CaseInsensitive)) {
            fileName += ".enc";
        }
        
        // Сохраняем шифрованный лог
        if (saveLogsToFile(fileName, true)) {
            ui->statusBar->showMessage("Зашифрованный лог успешно сохранен: " + fileName, 3000);
        }
    }
}

void MainWindow::onLoadEncryptedLog() {
    showPasswordDialog(false);
}

// Метод для загрузки логов с обновлением таблицы
void MainWindow::loadLogFile(const QString& filePath, const QString& password) {
    // Очищаем текущие данные
    ui->textEditLog->clear();
    suspiciousIPModel->clearRecords();
    
    // Создаем и показываем диалог прогресса загрузки
    QProgressDialog loadProgress("Загрузка файла логов...", "Отмена", 0, 100, this);
    loadProgress.setWindowModality(Qt::WindowModal);
    loadProgress.setMinimumDuration(0); // Показываем сразу
    loadProgress.setValue(0);
    loadProgress.show();
    QApplication::processEvents();
    
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        loadProgress.close();
        QMessageBox::critical(this, "Ошибка", "Не удалось открыть файл логов");
        return;
    }
    
    // Определяем, является ли файл зашифрованным по расширению
    bool isEncrypted = filePath.toLower().endsWith(".enc");
    QString content;
    
    // Показываем прогресс чтения файла
    loadProgress.setLabelText("Чтение файла...");
    loadProgress.setValue(10);
    QApplication::processEvents();
    
    // Чтение файла
    QByteArray fileData = file.readAll();
    file.close();
    
    // Если файл зашифрован, дешифруем его
    if (isEncrypted) {
        loadProgress.setLabelText("Дешифрование...");
        loadProgress.setValue(50);
        QApplication::processEvents();
        
        if (!password.isEmpty()) {
            QByteArray key = LogEncryption::generateKey(password);
            QByteArray decryptedData = LogEncryption::decrypt(fileData, key);
            
            if (decryptedData.isEmpty()) {
                loadProgress.close();
                QMessageBox::warning(this, "Ошибка", "Неверный пароль или файл поврежден");
                return;
            }
            
            content = QString::fromUtf8(decryptedData);
            ui->statusBar->showMessage("Зашифрованный лог успешно загружен", 3000);
        } else {
            loadProgress.close();
            QMessageBox::warning(this, "Ошибка", "Для расшифровки файла требуется пароль");
            return;
        }
    } else {
        // Незашифрованный файл
        content = QString::fromUtf8(fileData);
    }
    
    loadProgress.setLabelText("Анализ содержимого...");
    loadProgress.setValue(70);
    QApplication::processEvents();
    
    // Показываем прогресс обработки строк
    QProgressDialog progress("Обработка логов...", "Отмена", 0, content.count('\n') + 1, this);
    progress.setWindowModality(Qt::WindowModal);
    progress.show();
    
    // Разбиваем содержимое на строки и обрабатываем каждую
    QStringList lines = content.split('\n');
    for (int i = 0; i < lines.size(); i++) {
        // Обрабатываем строку и обновляем модель
        if (!lines[i].isEmpty()) {
            processLogLine(lines[i]);
        }
        
        // Обновляем прогресс
        progress.setValue(i + 1);
        if (progress.wasCanceled()) {
            break;
        }
        
        // Обрабатываем события для обновления интерфейса через каждые 100 строк
        if (i % 100 == 0) {
            QApplication::processEvents();
        }
    }
    
    statusBar()->showMessage(QString("Загружено %1 строк логов").arg(ui->textEditLog->document()->blockCount()), 3000);
    
    // Устанавливаем флаг, что логи загружены
    logsSaved = true;
}

// Функция для обработки строки лога с обновлением таблицы
void MainWindow::processLogLine(const QString& line) {
    QString cleanLine = line;
    cleanLine.remove('\r');
    
    // Определяем регулярные выражения
    QRegularExpression regexSuspicious("<span style='color:#FF0000; font-weight:bold;'>\\[(.*?)\\] (.*?) → (.*?): (.*?) \\(ПОДОЗРИТЕЛЬНЫЙ\\)</span>");
    QRegularExpression regexAlert("<span style='color:#FF0000; font-weight:bold; background-color:#FFEEEE;'>ПРЕДУПРЕЖДЕНИЕ: Обнаружена попытка атаки с (.*?) на (.*?) \\((.*?)\\)</span>");
    QRegularExpression regexPlainSuspicious("\\[(.*?)\\] (.*?) → (.*?): (.*?) \\(ПОДОЗРИТЕЛЬНЫЙ\\)");
    
    // Проверяем, является ли строка подозрительной
    bool isSuspicious = cleanLine.contains("ПОДОЗРИТЕЛЬНЫЙ", Qt::CaseInsensitive) || 
                        cleanLine.contains("ПРЕДУПРЕЖДЕНИЕ", Qt::CaseInsensitive) ||
                        regexSuspicious.match(cleanLine).hasMatch() || 
                        regexAlert.match(cleanLine).hasMatch() ||
                        regexPlainSuspicious.match(cleanLine).hasMatch();
    
    // Извлекаем данные из строки лога с помощью регулярных выражений
    QRegularExpression regexNormal("\\[(.*?)\\] (.*?) → (.*?): (.*?)$");
    
    QRegularExpressionMatch match;
    QString timestamp, sourceIP, destIP, packetType;
    
    if (isSuspicious) {
        // Проверяем разные форматы подозрительных строк
        match = regexSuspicious.match(cleanLine);
        if (match.hasMatch()) {
            timestamp = match.captured(1);
            sourceIP = match.captured(2);
            destIP = match.captured(3);
            packetType = match.captured(4);
        } else {
            match = regexAlert.match(cleanLine);
            if (match.hasMatch()) {
                timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss");
                sourceIP = match.captured(1);
                destIP = match.captured(2);
                packetType = match.captured(3);
            } else {
                // Попробуем распарсить формат без HTML-тегов
                match = regexPlainSuspicious.match(cleanLine);
                if (match.hasMatch()) {
                    timestamp = match.captured(1);
                    sourceIP = match.captured(2);
                    destIP = match.captured(3);
                    packetType = match.captured(4);
                }
            }
        }
        
        // Добавляем строку в журнал
        if (!sourceIP.isEmpty() && !destIP.isEmpty()) {
            ui->textEditLog->append(QString("<span style='color:#FF0000; font-weight:bold;'>[%1] %2 → %3: %4 (ПОДОЗРИТЕЛЬНЫЙ)</span>")
                                  .arg(timestamp)
                                  .arg(sourceIP)
                                  .arg(destIP)
                                  .arg(packetType));
            
            // Обновляем таблицу подозрительных IP
            suspiciousIPModel->addSuspiciousIP(sourceIP, destIP, packetType, timestamp);
        } else {
            // Если не удалось распарсить формат, просто добавляем строку как есть
            ui->textEditLog->append(cleanLine);
        }
    } else {
        // Обычный пакет
        match = regexNormal.match(cleanLine);
        if (match.hasMatch()) {
            timestamp = match.captured(1);
            sourceIP = match.captured(2);
            destIP = match.captured(3);
            packetType = match.captured(4);
            
            // Добавляем строку в журнал с обычным цветом (не зеленым)
            ui->textEditLog->append(QString("[%1] %2 → %3: %4")
                                  .arg(timestamp)
                                  .arg(sourceIP)
                                  .arg(destIP)
                                  .arg(packetType));
        } else {
            // Если строка не соответствует ни одному из форматов, добавляем как есть
            ui->textEditLog->append(cleanLine);
        }
    }
}

// Обработка события закрытия окна - перед закрытием предлагаем сохранить логи
void MainWindow::closeEvent(QCloseEvent *event)
{
    if (maybeSaveLog()) {
        // Принимаем событие закрытия
        event->accept();
    } else {
        // Отменяем событие закрытия, если пользователь отменил
        event->ignore();
    }
}

// Метод для сохранения логов
bool MainWindow::saveLogsToFile(const QString& fileName, bool encrypted) {
    if (ui->textEditLog->document()->isEmpty()) {
        return false; // нет данных для сохранения
    }
    
    if (encrypted && !lastEncryptionPassword.isEmpty()) {
        // Используем настоящее шифрование через PacketHandler
        QByteArray logData = ui->textEditLog->toPlainText().toUtf8();
        QByteArray key = LogEncryption::generateKey(lastEncryptionPassword);
        QByteArray encryptedData = LogEncryption::encrypt(logData, key);
        
        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(this, "Ошибка", "Не удалось сохранить файл логов.");
            return false;
        }
        
        file.write(encryptedData);
        file.close();
    } else {
        QFile file(fileName);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QMessageBox::warning(this, "Ошибка", "Не удалось сохранить файл логов.");
            return false;
        }
        
        QTextStream out(&file);
        // В Qt6 нет setCodec, QTextStream по умолчанию использует UTF-8
        out << ui->textEditLog->toPlainText();
        file.close();
    }
    
    logsSaved = true;
    return true;
}

// Метод для предложения сохранить логи перед выходом
bool MainWindow::maybeSaveLog() {
    // Если логи уже были сохранены или журнал пустой, не спрашиваем
    if (logsSaved || ui->textEditLog->document()->isEmpty()) {
        return true;
    }
    
    // Спрашиваем пользователя
    QMessageBox::StandardButton reply;
    QMessageBox messageBox(QMessageBox::Question,
                         "Сохранение логов", 
                         "Хотите сохранить текущие логи перед выходом?",
                         QMessageBox::NoButton,
                         this);
    QPushButton *yesButton = messageBox.addButton("Да", QMessageBox::YesRole);
    QPushButton *noButton = messageBox.addButton("Нет", QMessageBox::NoRole);
    QPushButton *cancelButton = messageBox.addButton("Отмена", QMessageBox::RejectRole);
    
    messageBox.exec();
    
    if (messageBox.clickedButton() == yesButton) {
        // Пользователь выбрал "Да" - спрашиваем, нужно ли шифрование
        QMessageBox encryptBox(QMessageBox::Question,
                            "Сохранение логов",
                            "Вы хотите сохранить логи с шифрованием?",
                            QMessageBox::NoButton,
                            this);
        QPushButton *encryptYesButton = encryptBox.addButton("Да", QMessageBox::YesRole);
        QPushButton *encryptNoButton = encryptBox.addButton("Нет", QMessageBox::NoRole);
        QPushButton *encryptCancelButton = encryptBox.addButton("Отмена", QMessageBox::RejectRole);
        
        encryptBox.exec();
        
        if (encryptBox.clickedButton() == encryptCancelButton) {
            return false;
        }
        
        bool useEncryption = (encryptBox.clickedButton() == encryptYesButton);
        
        // Выбираем соответствующий фильтр и расширение по умолчанию
        QString filter = useEncryption ? 
                        "Зашифрованные логи (*.enc);;Все файлы (*)" : 
                        "Файлы логов (*.log);;Все файлы (*)";
        
        QString defaultExt = useEncryption ? ".enc" : ".log";
        
        // Открываем диалог сохранения с правильным фильтром
        QString fileName = QFileDialog::getSaveFileName(this,
                                                      "Сохранить файл логов",
                                                      "logs" + defaultExt,
                                                      filter);
        
        if (fileName.isEmpty()) {
            // Пользователь отменил диалог сохранения
            return false;
        }
        
        // Проверяем и добавляем расширение, если оно отсутствует
        if (!fileName.endsWith(defaultExt, Qt::CaseInsensitive)) {
            fileName += defaultExt;
        }
        
        // Если выбрано шифрование, но пароль не задан, запрашиваем его
        if (useEncryption && lastEncryptionPassword.isEmpty()) {
            bool ok;
            QString password = QInputDialog::getText(
                this, 
                "Установка пароля шифрования", 
                "Введите пароль для шифрования логов:", 
                QLineEdit::Password, 
                "", 
                &ok
            );
            
            if (!ok || password.isEmpty()) {
                QMessageBox passwordWarnBox(QMessageBox::Warning, 
                                         "Предупреждение", 
                                         "Пароль не может быть пустым", 
                                         QMessageBox::NoButton, 
                                         this);
                passwordWarnBox.addButton("ОК", QMessageBox::AcceptRole);
                passwordWarnBox.exec();
                return false;
            }
            
            lastEncryptionPassword = password;
        }
        
        // Сохраняем файл
        return saveLogsToFile(fileName, useEncryption);
    } else if (messageBox.clickedButton() == noButton) {
        // Пользователь выбрал "Нет" - выходим без сохранения
        return true;
    } else {
        // Пользователь выбрал "Отмена" - отменяем выход
        return false;
    }
}

// Метод для отображения диалога "О программе"
void MainWindow::showAboutDialog()
{
    // Создаем текст с информацией о программе
    QString aboutText = 
        "<h2>Система обнаружения вторжений (IDS)</h2>"
        "<p><b>Версия:</b> 3.1.2</p>"
        "<p>Этот проект разработан в ознакомительных и учебных целях.</p>"
        "<p>Система предназначена для обнаружения и мониторинга подозрительной сетевой активности, "
        "включая сканирование портов, DOS-атаки и другие потенциальные угрозы.</p>"
        "<h3>Особенности:</h3>"
        "<ul>"
        "<li>Мониторинг сетевого трафика в реальном времени</li>"
        "<li>Обнаружение сканирования портов и DOS-атак</li>"
        "<li>Визуализация подозрительных IP-адресов</li>"
        "<li>Шифрование и сохранение логов</li>"
        "<li>Поддержка UTF-8 и кириллических символов</li>"
        "<li>Сохранение логов перед выходом из программы</li>"
        "</ul>"
        "<h3>Последние обновления:</h3>"
        "<ul>"
        "<li>Исправлена поддержка кодировки UTF-8 для правильного отображения кириллицы</li>"
        "<li>Усовершенствован интерфейс на русском языке</li>"
        "<li>Добавлен диалог подтверждения сохранения логов при выходе</li>"
        "<li>Улучшена работа с зашифрованными файлами логов</li>"
        "</ul>"
        "<p><b>ВАЖНО:</b> Данное программное обеспечение предназначено только для ознакомительных "
        "и образовательных целей. Использование для нарушения безопасности чужих систем запрещено.</p>"
        "<p>&copy; 2025. Все права защищены.</p>";
    
    // Создаем и настраиваем диалоговое окно
    QMessageBox aboutBox(this);
    aboutBox.setWindowTitle("О программе");
    aboutBox.setTextFormat(Qt::RichText);
    aboutBox.setText(aboutText);
    aboutBox.setIcon(QMessageBox::Information);
    
    // Заменяем стандартную кнопку "OK" на русскую версию
    aboutBox.setStandardButtons(QMessageBox::NoButton);
    aboutBox.addButton("ОК", QMessageBox::AcceptRole);
    
    // Устанавливаем минимальную ширину для лучшего отображения текста
    aboutBox.setMinimumWidth(500);
    
    // Показываем диалог
    aboutBox.exec();
}

// Метод для настройки меню приложения
void MainWindow::setupMenus() {
    // Находим существующее меню "Справка" и подключаем к нему обработчик
    QList<QAction*> actions = ui->menu_2->actions();
    for (QAction* action : actions) {
        if (action->text() == "О программе") {
            connect(action, &QAction::triggered, this, &MainWindow::showAboutDialog);
            break;
        }
    }
    
    // Создаем меню для шифрования логов
    QMenu* securityMenu = menuBar()->addMenu("Безопасность");
    
    QAction* encryptLogsAction = new QAction("Шифровать логи", this);
    encryptLogsAction->setCheckable(true);
    encryptLogsAction->setChecked(false);
    connect(encryptLogsAction, &QAction::toggled, this, &MainWindow::onEncryptionToggled);
    
    QAction* saveEncryptedLogAction = new QAction("Сохранить зашифрованный лог", this);
    connect(saveEncryptedLogAction, &QAction::triggered, this, &MainWindow::onSaveEncryptedLog);
    
    QAction* loadEncryptedLogAction = new QAction("Загрузить зашифрованный лог", this);
    connect(loadEncryptedLogAction, &QAction::triggered, this, &MainWindow::onLoadEncryptedLog);
    
    securityMenu->addAction(encryptLogsAction);
    securityMenu->addSeparator();
    securityMenu->addAction(saveEncryptedLogAction);
    securityMenu->addAction(loadEncryptedLogAction);
} 