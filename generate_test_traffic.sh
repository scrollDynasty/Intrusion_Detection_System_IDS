#!/bin/bash

# Цвета для вывода в терминал
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

# Функция для вывода информации
echo_info() {
    echo -e "${BLUE}[INFO]${RESET} $1"
}

# Функция для вывода предупреждений
echo_warning() {
    echo -e "${YELLOW}[ПРЕДУПРЕЖДЕНИЕ]${RESET} $1"
}

# Функция для вывода ошибок
echo_error() {
    echo -e "${RED}[ОШИБКА]${RESET} $1"
}

# Функция для вывода успеха
echo_success() {
    echo -e "${GREEN}[УСПЕХ]${RESET} $1"
}

# Проверка, запущено ли приложение от имени администратора
check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo_warning "Этот скрипт должен быть запущен от имени администратора для генерации сетевого трафика."
        echo_info "Пробуем запустить с sudo..."
        sudo "$0" "$@"
        exit $?
    fi
}

# Генерация TCP сканирования портов
generate_port_scan() {
    local target=$1
    local ports=$2
    
    echo_info "Генерация TCP сканирования портов на $target (порты: $ports)..."
    
    # Используем nmap для сканирования, если он установлен
    if command -v nmap &> /dev/null; then
        sudo nmap -sS -p $ports $target
    else
        # Иначе используем встроенный bash для простого сканирования
        echo_warning "nmap не найден, используем встроенные инструменты (менее эффективно)"
        for port in $(seq $ports | tr '-' ' '); do
            (echo > /dev/tcp/$target/$port) &>/dev/null && echo_success "Порт $port открыт" || echo_error "Порт $port закрыт"
            sleep 0.1
        done
    fi
}

# Генерация UDP флуда
generate_udp_flood() {
    local target=$1
    local port=$2
    local count=$3
    
    echo_info "Генерация UDP пакетов на $target:$port (количество: $count)..."
    
    # Используем hping3, если он установлен
    if command -v hping3 &> /dev/null; then
        sudo hping3 --udp -p $port -c $count $target
    else
        # Иначе используем другие инструменты
        echo_warning "hping3 не найден, проверяем наличие других инструментов"
        
        if command -v netcat &> /dev/null || command -v nc &> /dev/null; then
            NC_CMD="netcat"
            if ! command -v netcat &> /dev/null; then
                NC_CMD="nc"
            fi
            
            echo_info "Используем $NC_CMD для отправки UDP пакетов"
            for i in $(seq 1 $count); do
                echo "TEST PACKET $i" | $NC_CMD -u $target $port &>/dev/null
                echo_info "Отправлен UDP пакет $i на $target:$port"
                sleep 0.1
            done
        else
            echo_error "Не найдены инструменты для генерации UDP пакетов. Установите hping3 или netcat."
            exit 1
        fi
    fi
}

# Генерация ICMP флуда (ping)
generate_ping_flood() {
    local target=$1
    local count=$2
    
    echo_info "Генерация ICMP ping на $target (количество: $count)..."
    
    ping -c $count $target
}

# Главная функция
main() {
    echo -e "${BLUE}${BOLD}===============================================${RESET}"
    echo -e "${GREEN}${BOLD}    Генератор тестового трафика для IDS    ${RESET}"
    echo -e "${BLUE}${BOLD}===============================================${RESET}"
    echo
    
    echo_info "Этот скрипт генерирует различные типы сетевого трафика для тестирования IDS."
    echo_info "Убедитесь, что IDS запущена и мониторит сетевой интерфейс."
    echo
    
    # Запрашиваем выбор пользователя
    echo -e "${YELLOW}Выберите тип тестового трафика:${RESET}"
    echo "1. TCP сканирование портов (низкая интенсивность)"
    echo "2. TCP сканирование портов (высокая интенсивность)"
    echo "3. UDP флуд"
    echo "4. ICMP флуд (ping)"
    echo "5. Полный тест (все типы)"
    echo "q. Выход"
    echo
    
    echo -n "Введите номер выбранного теста [1-5,q]: "
    read choice
    
    # Определяем IP-адрес для тестирования (по умолчанию localhost)
    TARGET="127.0.0.1"
    echo_info "Используем целевой IP: $TARGET"
    
    case $choice in
        1)
            echo_info "Запуск TCP сканирования портов с низкой интенсивностью..."
            generate_port_scan $TARGET "20-30"
            ;;
        2)
            echo_info "Запуск TCP сканирования портов с высокой интенсивностью..."
            generate_port_scan $TARGET "1-100"
            ;;
        3)
            echo_info "Запуск UDP флуда..."
            generate_udp_flood $TARGET 53 30
            ;;
        4)
            echo_info "Запуск ICMP флуда (ping)..."
            generate_ping_flood $TARGET 30
            ;;
        5)
            echo_info "Запуск полного тестирования (все типы трафика)..."
            generate_port_scan $TARGET "20-30"
            generate_udp_flood $TARGET 53 20
            generate_ping_flood $TARGET 20
            generate_port_scan $TARGET "1-100"
            ;;
        q|Q|й|Й|exit|quit)
            echo_info "Выход из программы."
            exit 0
            ;;
        *)
            echo_error "Неверный выбор. Пожалуйста, попробуйте снова."
            echo
            main
            ;;
    esac
    
    echo
    echo_success "Тестирование завершено. Проверьте IDS на наличие обнаруженных подозрительных IP-адресов."
    echo_info "Нажмите Enter для продолжения..."
    read
}

# Проверка прав администратора
check_root

# Запуск программы
main 