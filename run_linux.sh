#!/bin/bash

# Проверка прав суперпользователя
if [ "$EUID" -ne 0 ]; then
    echo "Для перехвата сетевого трафика необходимы права root."
    echo "Пожалуйста, запустите скрипт с sudo: sudo $0 $*"
    exit 1
fi

# Путь к исполняемому файлу (относительно текущей директории)
EXECUTABLE="./build/Intrusion_Detection_System_IDS"

# Проверяем, существует ли исполняемый файл
if [ ! -f "$EXECUTABLE" ]; then
    echo "Исполняемый файл не найден: $EXECUTABLE"
    echo "Пожалуйста, сначала соберите проект с помощью ./build_linux.sh"
    exit 1
fi

# Проверяем, имеет ли файл права на выполнение
if [ ! -x "$EXECUTABLE" ]; then
    echo "Установка прав на выполнение для $EXECUTABLE"
    chmod +x "$EXECUTABLE"
fi

# Запускаем программу с переданными аргументами
echo "Запуск $EXECUTABLE с правами root..."
"$EXECUTABLE" "$@" 