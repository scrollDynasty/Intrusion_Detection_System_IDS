from scapy.all import *
import time

def send_syn_packets(target_ip, port=80, count=100):
    """
    Отправляет SYN-пакеты на указанный IP-адрес и порт.
    
    Args:
        target_ip (str): IP-адрес цели
        port (int): Порт назначения
        count (int): Количество пакетов для отправки
    """
    print(f"Отправка {count} SYN-пакетов на {target_ip}:{port}")
    
    # Создаем SYN-пакет
    packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
    
    # Отправляем пакеты
    send(packet, count=count, verbose=1)
    
    print("Отправка пакетов завершена!")

if __name__ == "__main__":
    # Запрашиваем IP-адрес у пользователя
    target_ip = input("Введите IP-адрес машины с IDS (например, 192.168.1.100): ")
    
    # Запрашиваем порт
    try:
        port = int(input("Введите порт назначения (по умолчанию 80): ") or "80")
    except ValueError:
        port = 80
        print("Некорректный порт, используется порт 80")
    
    # Запрашиваем количество пакетов
    try:
        count = int(input("Введите количество пакетов для отправки (по умолчанию 100): ") or "100")
    except ValueError:
        count = 100
        print("Некорректное количество, используется 100 пакетов")
    
    # Отправляем пакеты
    send_syn_packets(target_ip, port, count) 