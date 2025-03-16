#!/bin/bash

# Проверка наличия Docker
if ! command -v docker &> /dev/null; then
    echo "Docker не установлен. Пожалуйста, установите Docker Desktop для Mac."
    exit 1
fi

# Проверка наличия XQuartz
if ! command -v xquartz &> /dev/null; then
    echo "XQuartz не установлен. Пожалуйста, установите XQuartz."
    echo "Вы можете установить его с помощью Homebrew: brew install --cask xquartz"
    exit 1
fi

# Запуск XQuartz, если он еще не запущен
if ! pgrep -x "XQuartz" > /dev/null; then
    echo "Запуск XQuartz..."
    open -a XQuartz
    sleep 2
fi

# Разрешаем удаленные подключения к X-серверу
xhost +localhost

# Получаем IP-адрес хоста
IP=$(ifconfig en0 | grep inet | awk '$1=="inet" {print $2}')
echo "IP-адрес хоста: $IP"

# Устанавливаем переменную DISPLAY
export DISPLAY=$IP:0

# Запускаем контейнер
docker-compose up --build

# Закрываем доступ к X-серверу после завершения
xhost -localhost 