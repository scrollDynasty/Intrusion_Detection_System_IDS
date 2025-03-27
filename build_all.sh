#!/bin/bash

# Цвета для вывода в терминал
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Функция для проверки наличия build.sh и build_ssh.sh
check_build_scripts() {
    if [ ! -f "build.sh" ]; then
        echo -e "${RED}Ошибка: Не найден скрипт build.sh!${RESET}"
        return 1
    fi
    
    if [ ! -f "build_ssh.sh" ]; then
        echo -e "${RED}Ошибка: Не найден скрипт build_ssh.sh!${RESET}"
        return 1
    fi
    
    return 0
}

# Главная функция
main() {
    echo -e "${BLUE}${BOLD}===============================================${RESET}"
    echo -e "${GREEN}${BOLD}    Сборка Системы обнаружения вторжений (IDS)${RESET}"
    echo -e "${BLUE}${BOLD}===============================================${RESET}"
    echo
    
    # Проверяем наличие скриптов сборки
    check_build_scripts
    if [ $? -ne 0 ]; then
        echo
        read -p "Нажмите Enter для выхода..."
        exit 1
    fi
    
    # Сборка GUI-версии
    echo -e "${YELLOW}Сборка GUI-версии...${RESET}"
    chmod +x build.sh
    ./build.sh
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Ошибка при сборке GUI-версии!${RESET}"
        echo
        read -p "Нажмите Enter для продолжения сборки SSH-версии..."
    else
        echo -e "${GREEN}GUI-версия успешно собрана!${RESET}"
    fi
    
    echo
    
    # Сборка SSH-версии
    echo -e "${YELLOW}Сборка SSH-версии...${RESET}"
    chmod +x build_ssh.sh
    ./build_ssh.sh
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Ошибка при сборке SSH-версии!${RESET}"
        echo
        read -p "Нажмите Enter для выхода..."
        exit 1
    else
        echo -e "${GREEN}SSH-версия успешно собрана!${RESET}"
    fi
    
    echo
    echo -e "${GREEN}${BOLD}Обе версии успешно собраны!${RESET}"
    echo
    
    # Делаем launcher.sh исполняемым
    chmod +x launcher.sh
    
    # Спрашиваем, хочет ли пользователь запустить программу сразу
    echo -n "Запустить программу сейчас? [y/n]: "
    read choice
    
    if [[ "$choice" == "y" || "$choice" == "Y" || "$choice" == "д" || "$choice" == "Д" ]]; then
        ./launcher.sh
    else
        echo -e "${BLUE}Для запуска программы используйте команду: ${YELLOW}./launcher.sh${RESET}"
    fi
}

# Запуск программы
main 