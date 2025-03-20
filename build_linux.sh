#!/bin/bash

# Проверка на Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "Этот скрипт предназначен только для Linux!"
    exit 1
fi

# Проверка наличия необходимых программ
MISSING_DEPS=0

check_dependency() {
    which $1 > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "ОШИБКА: $1 не найден"
        MISSING_DEPS=1
    else
        echo "OK: $1 найден"
    fi
}

echo "Проверка зависимостей..."
check_dependency cmake
check_dependency make
check_dependency g++
check_dependency pkg-config

# Проверка libpcap
pkg-config --exists libpcap
if [ $? -ne 0 ]; then
    echo "ОШИБКА: libpcap не найден"
    MISSING_DEPS=1
else
    echo "OK: libpcap найден"
fi

# Проверка Qt
if [ -z "$(pkg-config --list-all | grep -E 'Qt6Core|Qt5Core')" ]; then
    echo "ОШИБКА: Qt не найден"
    MISSING_DEPS=1
else
    echo "OK: Qt найден"
fi

if [ $MISSING_DEPS -ne 0 ]; then
    echo "Необходимые зависимости не установлены."
    echo "Пожалуйста, установите недостающие зависимости и запустите скрипт снова."
    echo "См. README_LINUX.md для инструкций по установке зависимостей."
    exit 1
fi

# Создание папки для сборки, если она не существует
mkdir -p build
cd build

# Запуск CMake и сборка
echo "Запуск CMake..."
cmake ..
if [ $? -ne 0 ]; then
    echo "ОШИБКА: CMake завершился с ошибкой"
    exit 1
fi

echo "Сборка проекта..."
make -j$(nproc)
if [ $? -ne 0 ]; then
    echo "ОШИБКА: Сборка завершилась с ошибкой"
    exit 1
fi

echo "Сборка успешно завершена!"
echo "Для запуска программы выполните: sudo ./Intrusion_Detection_System_IDS" 