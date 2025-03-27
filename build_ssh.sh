#!/bin/bash

# Скрипт для сборки Системы обнаружения вторжений (IDS) в SSH-режиме (без GUI)

echo "Сборка Системы обнаружения вторжений (IDS) в SSH-режиме (без GUI)..."

# Проверка наличия необходимых пакетов
echo "Проверка наличия необходимых пакетов..."

# Массив необходимых пакетов
required_packages=("cmake" "build-essential" "libssl-dev" "libpcap-dev")

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
if [ ! -d "build_ssh" ]; then
    mkdir -p build_ssh
fi

# Переходим в директорию сборки
cd build_ssh

# Генерируем Makefile с помощью CMake, только для SSH-версии
echo "Генерируем файлы сборки с помощью CMake (только SSH-версия)..."
cmake -DBUILD_SSH_ONLY=ON ..

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

# Проверяем, что SSH-версия собрана успешно
if [ -f "Intrusion_Detection_System_IDS_SSH" ]; then
    echo "Сборка успешно завершена!"
    echo "Для запуска используйте: sudo ./run_ssh.sh [ОПЦИИ]"
    echo "Доступные опции:"
    echo "  -a, --adapter <индекс>  Указать индекс сетевого интерфейса"
    echo "  -v, --verbose           Включить подробный режим вывода"
    echo "  -t, --test              Запустить в тестовом режиме (симуляция трафика)"
    echo "  -s, --service           Запустить как системный сервис"
    echo "  -e, --encrypt <пароль>  Установить пароль шифрования"
    
    # Копируем исполняемый файл в корневую директорию проекта
    cp Intrusion_Detection_System_IDS_SSH ..
    
    # Устанавливаем разрешения на выполнение
    chmod +x ../Intrusion_Detection_System_IDS_SSH
else
    echo "Ошибка: Не удалось найти скомпилированный файл"
    exit 1
fi

# Создаем директорию для логов, если не существует
if [ ! -d "../logs" ]; then
    mkdir -p ../logs
    echo "Создана директория для хранения зашифрованных логов: logs/"
fi

exit 0 