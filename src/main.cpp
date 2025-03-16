#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <QApplication>
#include <QMessageBox>
#include <QStyleFactory>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QFile>
#include <QTextStream>
#include "MainWindow.h"
#include "PacketHandler.h"

#pragma comment(lib, "Ws2_32.lib")

// Функция для загрузки и применения стилей
void applyStyles(QApplication& app) {
    QFile styleFile(":/resources/style.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        QTextStream stream(&styleFile);
        app.setStyleSheet(stream.readAll());
        styleFile.close();
    } else {
        qWarning("Не удалось загрузить файл стилей");
    }
}

int main(int argc, char *argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    QApplication app(argc, argv);
    
    // Применяем стили
    applyStyles(app);
    
    // Настраиваем парсер командной строки
    QCommandLineParser parser;
    parser.setApplicationDescription("Intrusion Detection System");
    parser.addHelpOption();
    
    // Добавляем опцию для указания сетевого адаптера
    QCommandLineOption adapterOption(QStringList() << "a" << "adapter",
                                    "Specify network adapter name",
                                    "adapter");
    parser.addOption(adapterOption);
    
    // Парсим аргументы командной строки
    parser.process(app);
    
    // Проверяем, указан ли адаптер в командной строке
    QString adapterName;
    if (parser.isSet(adapterOption)) {
        adapterName = parser.value(adapterOption);
    }
    
    // Устанавливаем стиль приложения (базовый стиль)
    app.setStyle(QStyleFactory::create("Fusion"));
    
    // Создаем и показываем главное окно
    MainWindow mainWindow;
    
    // Если указан адаптер в командной строке, запускаем захват пакетов
    if (!adapterName.isEmpty()) {
        PacketHandler packetHandler;
        if (packetHandler.startCapture(adapterName.toStdString())) {
            QMessageBox::information(&mainWindow, "Информация", 
                                    QString("Захват пакетов запущен на адаптере: %1").arg(adapterName));
        } else {
            QMessageBox::critical(&mainWindow, "Ошибка", 
                                 QString("Не удалось запустить захват пакетов на адаптере: %1").arg(adapterName));
        }
    }
    
    mainWindow.show();
    
    // Запускаем цикл обработки событий
    return app.exec();
}
