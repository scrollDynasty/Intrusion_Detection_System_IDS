# Intrusion Detection System (IDS) для Linux

## Требования

Для сборки и запуска IDS на Linux необходимо установить следующие компоненты:

1. **Qt 6.x** - для графического интерфейса
2. **libpcap** - для перехвата сетевого трафика
3. **CMake** - для сборки проекта
4. **Компилятор C++** (gcc/g++ или clang)

## Установка зависимостей

### Ubuntu/Debian:

```bash
# Обновление репозиториев
sudo apt update

# Установка Qt 6
sudo apt install qt6-base-dev qt6-tools-dev libqt6widgets6 libqt6gui6 libqt6core6 libqt6network6

# Установка libpcap
sudo apt install libpcap-dev

# Установка CMake и компилятора
sudo apt install cmake build-essential
```

### Fedora:

```bash
# Установка Qt 6
sudo dnf install qt6-qtbase-devel qt6-tools-dev

# Установка libpcap
sudo dnf install libpcap-devel

# Установка CMake и компилятора
sudo dnf install cmake gcc-c++
```

### Arch Linux:

```bash
# Установка Qt 6
sudo pacman -S qt6-base qt6-tools

# Установка libpcap
sudo pacman -S libpcap

# Установка CMake и компилятора
sudo pacman -S cmake gcc
```

## Сборка проекта

### Вариант 1: Использование скрипта сборки (рекомендуется)

```bash
# Дать права на выполнение скрипту
chmod +x build_linux.sh

# Запустить сборку
./build_linux.sh
```

### Вариант 2: Ручная сборка

1. Создание директории для сборки:
   ```bash
   mkdir -p build
   cd build
   ```

2. Запуск CMake и сборка:
   ```bash
   cmake ..
   make -j$(nproc)
   ```

## Запуск IDS

### Вариант 1: Использование скрипта запуска (рекомендуется)

```bash
# Дать права на выполнение скрипту
chmod +x run_linux.sh

# Запустить программу с правами root
sudo ./run_linux.sh
```

### Вариант 2: Ручной запуск

Для корректной работы IDS требуются права root, так как программа использует libpcap для перехвата сетевых пакетов:

```bash
# Запуск из директории build
sudo ./Intrusion_Detection_System_IDS
```

Для запуска с указанием конкретного сетевого интерфейса:

```bash
sudo ./Intrusion_Detection_System_IDS --adapter=eth0
```

## Особенности работы на Linux

1. Список доступных сетевых интерфейсов отображается в главном окне программы. Виртуальный интерфейс "test0" всегда присутствует для тестирования функциональности.

2. Для запуска мониторинга сети необходимы права root.

3. Для запуска тестовых атак из инструментария программы также могут потребоваться права root.

## Типичные ошибки и их решение

### 1. Ошибки совместимости структур заголовков TCP/IP

Если при сборке возникают ошибки вида:
```
error: 'const ids_tcp_hdr' has no member named 'src_port'
error: 'const ids_tcp_hdr' has no member named 'flags'
```

**Решение:**
В Linux системные структуры TCP/IP имеют другие имена полей. Необходимо заменить:
- `src_port` на `th_sport`
- `dst_port` на `th_dport`
- `flags` на `th_flags`

Также для флагов TCP используйте предопределенные константы:
- `TH_SYN` вместо `0x02` (SYN флаг)
- `TH_ACK` вместо `0x10` (ACK флаг)
- `TH_FIN` вместо `0x01` (FIN флаг)
- `TH_RST` вместо `0x04` (RST флаг)

### 2. Ошибки с typedef и struct

Если вы видите ошибки вида:
```
error: using typedef-name 'ids_ip_hdr' after 'struct'
```

**Решение:**
Не используйте ключевое слово `struct` перед типами, определенными через typedef:

```cpp
// Неправильно:
const struct ids_ip_hdr *ipHeader = ...

// Правильно:
const ids_ip_hdr *ipHeader = ...
```

### 3. Ошибки с отображением интерфейса

Если графический интерфейс не запускается или выглядит некорректно:

**Решение:**
```bash
# Установка всех необходимых библиотек Qt
sudo apt install libqt6widgets6 libqt6gui6 libqt6core6 libqt6network6

# Проверка переменных окружения Qt
echo $QT_PLUGIN_PATH
echo $LD_LIBRARY_PATH

# Если используете Wayland и есть проблемы с отображением
export QT_QPA_PLATFORM=xcb
```

### 4. Ошибки при запуске захвата пакетов

Если программа не может захватывать пакеты:

**Решение:**
```bash
# Проверка наличия libpcap
ldconfig -p | grep pcap

# Проверка прав доступа к сетевым интерфейсам
sudo setcap cap_net_raw,cap_net_admin=eip ./Intrusion_Detection_System_IDS

# Добавление пользователя в группу wireshark (если установлен)
sudo usermod -a -G wireshark $USER
# После этого требуется перелогин
```

### 5. Переполнение буфера для текста

Если вы видите предупреждения о переполнении буфера:

**Решение:**
```cpp
// Используйте ASCII-символы или короткие строки для буферов фиксированного размера
strcpy(sourceIP, "unknown"); // вместо кириллических символов
```

## Тестирование без прав root

Для тестирования функциональности без прав root можно использовать тестовый режим:

```bash
./Intrusion_Detection_System_IDS --test-mode
```

В этом режиме программа будет использовать виртуальный интерфейс "test0" и генерировать тестовые пакеты для демонстрации функциональности.

## Лицензия

[Информация о лицензии] 