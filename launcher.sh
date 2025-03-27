#!/bin/bash

# Цвета для вывода в терминал
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Функция для рисования рамки
draw_box() {
    local width=60
    local header="$1"
    
    echo -e "${BLUE}"
    printf "╔"
    printf "═%.0s" $(seq 1 $width)
    printf "╗\n"
    
    printf "║ %-$(($width-1))s║\n" "$header"
    
    printf "╠"
    printf "═%.0s" $(seq 1 $width)
    printf "╣\n"
    
    printf "║ %-$(($width-1))s║\n" "Выберите режим запуска:"
    printf "║ %-$(($width-1))s║\n" ""
    printf "║ %-$(($width-1))s║\n" "  1. ${GREEN}GUI${BLUE} режим (с графическим интерфейсом)"
    printf "║ %-$(($width-1))s║\n" "  2. ${YELLOW}SSH${BLUE} режим (консольный)"
    printf "║ %-$(($width-1))s║\n" "  q. ${RED}Выход${BLUE}"
    printf "║ %-$(($width-1))s║\n" ""
    
    printf "╚"
    printf "═%.0s" $(seq 1 $width)
    printf "╝\n"
    echo -e "${RESET}"
}

# Функция для проверки наличия необходимых файлов
check_files() {
    if [ ! -f "build/Intrusion_Detection_System_IDS" ] && [ ! -f "Intrusion_Detection_System_IDS" ]; then
        echo -e "${RED}Ошибка: Не найден исполняемый файл GUI-версии!${RESET}"
        echo -e "${YELLOW}Сначала выполните сборку с помощью ./build.sh${RESET}"
        return 1
    fi
    
    if [ ! -f "build_ssh/Intrusion_Detection_System_IDS_SSH" ] && [ ! -f "Intrusion_Detection_System_IDS_SSH" ]; then
        echo -e "${RED}Ошибка: Не найден исполняемый файл SSH-версии!${RESET}"
        echo -e "${YELLOW}Сначала выполните сборку с помощью ./build_ssh.sh${RESET}"
        return 1
    fi
    
    return 0
}

# Функция для запуска GUI-версии
run_gui() {
    if [ -f "Intrusion_Detection_System_IDS" ]; then
        ./Intrusion_Detection_System_IDS
    else
        ./build/Intrusion_Detection_System_IDS
    fi
}

# Функция для запуска SSH-версии
run_ssh() {
    if [ -f "Intrusion_Detection_System_IDS_SSH" ]; then
        sudo ./Intrusion_Detection_System_IDS_SSH
    else
        sudo ./build_ssh/Intrusion_Detection_System_IDS_SSH
    fi
}

# Главная функция
main() {
    clear
    draw_box "Система обнаружения вторжений (IDS)"
    
    # Проверяем наличие необходимых файлов
    check_files
    if [ $? -ne 0 ]; then
        echo
        read -p "Нажмите Enter для выхода..."
        exit 1
    fi
    
    # Запрашиваем выбор пользователя
    echo -n "Введите номер выбранного режима [1,2,q]: "
    read choice
    
    case $choice in
        1)
            echo -e "${GREEN}Запуск в режиме GUI...${RESET}"
            run_gui
            ;;
        2)
            echo -e "${YELLOW}Запуск в режиме SSH...${RESET}"
            run_ssh
            ;;
        q|Q|й|Й|exit|quit)
            echo -e "${RED}Выход из программы.${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}Неверный выбор. Пожалуйста, попробуйте снова.${RESET}"
            echo
            read -p "Нажмите Enter для продолжения..."
            main
            ;;
    esac
}

# Запуск программы
main 