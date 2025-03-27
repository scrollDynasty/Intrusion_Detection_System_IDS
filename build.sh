#!/bin/bash

# Скрипт для сборки Системы обнаружения вторжений (IDS) в GUI-режиме

echo "Сборка Системы обнаружения вторжений (IDS) с графическим интерфейсом..."

# Проверка наличия необходимых пакетов
echo "Проверка наличия необходимых пакетов..."

# Массив необходимых пакетов
required_packages=("cmake" "build-essential" "libssl-dev" "libpcap-dev" "qtbase5-dev" "qttools5-dev" "qttools5-dev-tools")

# Проверяем и устанавливаем отсутствующие пакеты
for package in "${required_packages[@]}"; do
    if dpkg -s "$package" >/dev/null 2>&1; then
        echo "Пакет $package уже установлен"
    else
        echo "Установка пакета $package..."
        sudo apt-get install -y "$package"
        if [ $? -ne 0 ]; then
            echo "Ошибка: Не удалось установить пакет $package"
            exit 1
        fi
    fi
done

# Создаем директорию для сборки, если она не существует
if [ ! -d "build" ]; then
    mkdir -p build
fi

# Переходим в директорию сборки
cd build

# Генерируем Makefile с помощью CMake
echo "Генерируем файлы сборки с помощью CMake..."
cmake ..

if [ $? -ne 0 ]; then
    echo "Ошибка: Не удалось сгенерировать файлы сборки"
    exit 1
fi

# Компилируем проект
echo "Компилируем проект..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    echo "Ошибка: Не удалось собрать проект"
    exit 1
fi

# Проверяем, что GUI-версия собрана успешно
if [ -f "Intrusion_Detection_System_IDS" ]; then
    echo "Сборка GUI-версии успешно завершена!"
    echo "Для запуска используйте: ./Intrusion_Detection_System_IDS"
    
    # Копируем исполняемый файл в корневую директорию проекта
    cp Intrusion_Detection_System_IDS ..
    
    # Устанавливаем разрешения на выполнение
    chmod +x ../Intrusion_Detection_System_IDS
else
    echo "Ошибка: Не удалось найти скомпилированный файл GUI-версии"
    exit 1
fi

# Создаем директорию для логов, если не существует
if [ ! -d "../logs" ]; then
    mkdir -p ../logs
    echo "Создана директория для хранения логов: logs/"
fi

exit 0 