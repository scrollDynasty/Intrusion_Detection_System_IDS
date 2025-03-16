#!/bin/bash

# Проверка наличия Docker
if ! command -v docker &> /dev/null; then
    echo "Docker не установлен. Пожалуйста, установите Docker."
    exit 1
fi

# Проверка наличия docker-compose
if ! command -v docker-compose &> /dev/null; then
    echo "docker-compose не установлен. Пожалуйста, установите docker-compose."
    exit 1
fi

# Разрешаем доступ к X-серверу
xhost +local:docker

# Запускаем контейнер
docker-compose up --build

# Закрываем доступ к X-серверу после завершения
xhost -local:docker 