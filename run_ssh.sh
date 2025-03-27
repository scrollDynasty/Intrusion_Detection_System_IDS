#!/bin/bash

# Скрипт для запуска Системы обнаружения вторжений (IDS) в SSH-режиме

echo "Запуск Системы обнаружения вторжений (IDS) в SSH-режиме..."

# Определяем текущую директорию
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Функция для вывода помощи
print_help() {
    echo "Использование: $0 [ОПЦИИ]"
    echo "Опции:"
    echo "  -a, --adapter <индекс>   Индекс сетевого интерфейса"
    echo "  -v, --verbose            Включить подробный режим вывода"
    echo "  -t, --test               Запустить в тестовом режиме"
    echo "  -s, --service            Запустить как системный сервис"
    echo "  -e, --encrypt <пароль>   Установить пароль шифрования"
    echo "  -h, --help               Показать эту справку"
    echo "  --version                Показать версию программы"
    echo ""
    echo "Примеры:"
    echo "  $0 -a 1                  Запустить с интерфейсом 1"
    echo "  $0 -t -v                 Запустить в тестовом режиме с подробным выводом"
    echo "  $0 -e secret123          Запустить с шифрованием логов и паролем 'secret123'"
}

# Проверяем, запущен ли скрипт с правами root
if [ "$(id -u)" != "0" ]; then
    echo "Внимание: Для захвата сетевого трафика необходимы права root."
    echo "Пожалуйста, запустите скрипт с использованием sudo:"
    echo "sudo $0 $*"
    exit 1
fi

# Парсим аргументы командной строки
ADAPTER_INDEX=""
VERBOSE=""
TEST_MODE=""
SERVICE_MODE=""
ENCRYPT_PASSWORD=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -a|--adapter)
            ADAPTER_INDEX="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE="--verbose"
            shift
            ;;
        -t|--test)
            TEST_MODE="--test"
            shift
            ;;
        -s|--service)
            SERVICE_MODE="--service"
            shift
            ;;
        -e|--encrypt)
            ENCRYPT_PASSWORD="$2"
            shift 2
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        --version)
            echo "Система обнаружения вторжений (IDS-SSH) версия 1.0.0"
            exit 0
            ;;
        *)
            echo "Неизвестная опция: $1"
            print_help
            exit 1
            ;;
    esac
done

# Формируем параметры запуска
PARAMS=""
if [ -n "$ADAPTER_INDEX" ]; then
    PARAMS="$PARAMS --adapter $ADAPTER_INDEX"
fi

if [ -n "$VERBOSE" ]; then
    PARAMS="$PARAMS $VERBOSE"
fi

if [ -n "$TEST_MODE" ]; then
    PARAMS="$PARAMS $TEST_MODE"
fi

if [ -n "$SERVICE_MODE" ]; then
    PARAMS="$PARAMS $SERVICE_MODE"
fi

if [ -n "$ENCRYPT_PASSWORD" ]; then
    PARAMS="$PARAMS --encrypt $ENCRYPT_PASSWORD"
fi

# Проверяем наличие исполняемого файла
if [ -f "./build/Intrusion_Detection_System_IDS_SSH" ]; then
    # Запускаем программу из директории сборки
    ./build/Intrusion_Detection_System_IDS_SSH $PARAMS
else
    # Проверяем, есть ли директория build
    if [ ! -d "./build" ]; then
        echo "Директория сборки не найдена. Создаем..."
        mkdir -p build
    fi
    
    # Переходим в директорию сборки
    cd build
    
    # Проверяем наличие OpenSSL
    if ! pkg-config --exists openssl; then
        echo "OpenSSL не найден. Устанавливаем..."
        sudo apt-get install -y libssl-dev
    fi
    
    # Генерируем Makefile с помощью CMake
    echo "Генерируем файлы сборки с помощью CMake..."
    cmake ..
    
    # Компилируем проект
    echo "Компилируем проект..."
    make -j$(nproc)
    
    # Проверяем успешность сборки
    if [ -f "Intrusion_Detection_System_IDS_SSH" ]; then
        echo "Сборка завершена успешно!"
        # Запускаем программу
        ./Intrusion_Detection_System_IDS_SSH $PARAMS
    else
        echo "Ошибка: Не удалось собрать проект."
        exit 1
    fi
fi

exit 0 