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
#include <QDebug>
#include <QDateTime>
#include <QMutex>
#include "MainWindow.h"
#include "PacketHandler.h"

#pragma comment(lib, "Ws2_32.lib")

// Глобальный мьютекс для синхронизации доступа к файлу лога
QMutex logMutex;

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

// Обработчик сообщений для перенаправления вывода в файл лога
void messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    // Блокируем мьютекс для безопасного доступа к файлу
    QMutexLocker locker(&logMutex);
    
    // Открываем файл для каждого сообщения
    QFile logFile("ids_log.txt");
    if (!logFile.open(QIODevice::Append | QIODevice::Text)) {
        // Если не удалось открыть файл, выводим сообщение в стандартный вывод
        fprintf(stderr, "Не удалось открыть файл лога\n");
        return;
    }
    
    QTextStream out(&logFile);
    QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");
    
    switch (type) {
        case QtDebugMsg:
            out << timestamp << " [DEBUG] " << msg << "\n";
            break;
        case QtInfoMsg:
            out << timestamp << " [INFO] " << msg << "\n";
            break;
        case QtWarningMsg:
            out << timestamp << " [WARNING] " << msg << "\n";
            break;
        case QtCriticalMsg:
            out << timestamp << " [CRITICAL] " << msg << "\n";
            break;
        case QtFatalMsg:
            out << timestamp << " [FATAL] " << msg << "\n";
            // Не вызываем abort() здесь, чтобы не завершать программу аварийно
            break;
    }
    
    // Сбрасываем буфер и закрываем файл
    out.flush();
    logFile.close();
    
    // Дублируем вывод в консоль
    fprintf(stderr, "%s\n", qPrintable(msg));
}

int main(int argc, char *argv[]) {
    // Устанавливаем обработчик сообщений для перенаправления вывода в файл
    qInstallMessageHandler(messageHandler);
    
    // Инициализируем кодировку для консоли
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

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
