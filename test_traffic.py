#!/usr/bin/env python3
import socket
import time
import random
import sys

def generate_tcp_traffic(target_ip, port, count=10):
    """Генерирует TCP трафик, пытаясь подключиться к указанному порту"""
    print(f"Генерация {count} TCP пакетов к {target_ip}:{port}")
    
    for i in range(count):
        try:
            # Создаем TCP сокет
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)  # Устанавливаем таймаут
            
            # Пытаемся подключиться
            result = s.connect_ex((target_ip, port))
            
            # Закрываем сокет
            s.close()
            
            print(f"Пакет {i+1}/{count}: TCP -> {target_ip}:{port} (результат: {result})")
            time.sleep(0.5)  # Пауза между пакетами
            
        except Exception as e:
            print(f"Ошибка при отправке TCP пакета: {e}")

def generate_udp_traffic(target_ip, port, count=10):
    """Генерирует UDP трафик, отправляя данные на указанный порт"""
    print(f"Генерация {count} UDP пакетов к {target_ip}:{port}")
    
    for i in range(count):
        try:
            # Создаем UDP сокет
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Отправляем данные
            message = f"Test UDP packet {i+1}".encode()
            s.sendto(message, (target_ip, port))
            
            # Закрываем сокет
            s.close()
            
            print(f"Пакет {i+1}/{count}: UDP -> {target_ip}:{port}")
            time.sleep(0.5)  # Пауза между пакетами
            
        except Exception as e:
            print(f"Ошибка при отправке UDP пакета: {e}")

def generate_icmp_traffic(target_ip, count=5):
    """Генерирует ICMP трафик (ping)"""
    print(f"Отправка {count} ICMP ping-запросов к {target_ip}")
    
    # В Windows используем системную команду ping
    import subprocess
    try:
        subprocess.run(["ping", "-n", str(count), target_ip], check=True)
    except Exception as e:
        print(f"Ошибка при выполнении ping: {e}")

def main():
    # Проверяем аргументы командной строки
    if len(sys.argv) < 2:
        target_ip = "127.0.0.1"  # По умолчанию используем localhost
        print(f"IP-адрес не указан, используем {target_ip}")
    else:
        target_ip = sys.argv[1]
    
    # Генерируем разные типы трафика
    print("=== Генерация тестового сетевого трафика ===")
    
    # TCP трафик на разные порты
    tcp_ports = [80, 443, 8080, 22, 21]
    for port in tcp_ports:
        generate_tcp_traffic(target_ip, port, count=3)
    
    # UDP трафик
    udp_ports = [53, 123, 161, 1900]
    for port in udp_ports:
        generate_udp_traffic(target_ip, port, count=3)
    
    # ICMP трафик (ping)
    generate_icmp_traffic(target_ip)
    
    print("Генерация тестового трафика завершена!")

if __name__ == "__main__":
    main() 