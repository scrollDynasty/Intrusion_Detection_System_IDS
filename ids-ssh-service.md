# Установка IDS в качестве системного сервиса

В этом документе описывается процесс установки Системы обнаружения вторжений (IDS) в качестве системного сервиса на Linux-серверах.

## Требования

- Операционная система Linux (Ubuntu, Debian, CentOS, Fedora и т.д.)
- Права суперпользователя (root)
- Установленные зависимости:
  - libpcap
  - Qt6 Core
  - CMake
  - Компилятор C++

## Шаги установки

### 1. Сборка IDS-SSH

Сначала соберите SSH-версию IDS с помощью предоставленного скрипта:

```bash
./build_ssh.sh
```

### 2. Создание файла службы systemd

Создайте файл службы systemd для IDS:

```bash
sudo nano /etc/systemd/system/ids-ssh.service
```

Скопируйте и вставьте следующее содержимое:

```ini
[Unit]
Description=Intrusion Detection System SSH Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ids-ssh
ExecStart=/opt/ids-ssh/Intrusion_Detection_System_IDS_SSH --service --adapter 1
Restart=on-failure
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ids-ssh

[Install]
WantedBy=multi-user.target
```

> **Примечание**: Замените параметр `--adapter 1` на индекс сетевого интерфейса, который вы хотите мониторить. Чтобы узнать список доступных интерфейсов, запустите программу с опцией `--help`.

### 3. Создание директории установки и копирование файлов

```bash
# Создаем директорию для установки
sudo mkdir -p /opt/ids-ssh

# Копируем исполняемый файл и необходимые ресурсы
sudo cp build/Intrusion_Detection_System_IDS_SSH /opt/ids-ssh/
sudo cp -r resources/ /opt/ids-ssh/
sudo cp -r sounds/ /opt/ids-ssh/
```

### 4. Разрешение на выполнение

```bash
sudo chmod +x /opt/ids-ssh/Intrusion_Detection_System_IDS_SSH
```

### 5. Перезагрузка демона systemd и запуск службы

```bash
# Перезагрузка конфигурации systemd
sudo systemctl daemon-reload

# Включение службы для запуска при загрузке системы
sudo systemctl enable ids-ssh.service

# Запуск службы
sudo systemctl start ids-ssh.service
```

### 6. Проверка статуса

```bash
sudo systemctl status ids-ssh.service
```

Вы должны увидеть, что служба запущена и работает.

## Просмотр журналов

Для просмотра журналов работы IDS-SSH используйте следующую команду:

```bash
sudo journalctl -u ids-ssh.service -f
```

Опция `-f` позволяет следить за логами в режиме реального времени.

## Управление службой

### Останов службы

```bash
sudo systemctl stop ids-ssh.service
```

### Перезапуск службы

```bash
sudo systemctl restart ids-ssh.service
```

### Отключение автозапуска

```bash
sudo systemctl disable ids-ssh.service
```

## Изменение конфигурации

Если вам необходимо изменить параметры запуска IDS, отредактируйте файл службы:

```bash
sudo nano /etc/systemd/system/ids-ssh.service
```

После внесения изменений не забудьте перезагрузить конфигурацию systemd и перезапустить службу:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ids-ssh.service
```

## Удаление службы

```bash
# Останавливаем и отключаем службу
sudo systemctl stop ids-ssh.service
sudo systemctl disable ids-ssh.service

# Удаляем файл службы
sudo rm /etc/systemd/system/ids-ssh.service

# Перезагружаем конфигурацию systemd
sudo systemctl daemon-reload

# Удаляем установленные файлы
sudo rm -rf /opt/ids-ssh/
```

## Решение проблем

### Служба не запускается

Проверьте журналы systemd:

```bash
sudo journalctl -u ids-ssh.service -n 50
```

Это покажет последние 50 строк журнала службы.

### Проблемы с правами доступа

Убедитесь, что служба запускается от имени пользователя root, так как для захвата сетевого трафика требуются повышенные привилегии.

### Не обнаруживаются сетевые интерфейсы

Запустите программу вручную, чтобы увидеть список доступных сетевых интерфейсов:

```bash
sudo /opt/ids-ssh/Intrusion_Detection_System_IDS_SSH
```

Затем выберите нужный индекс интерфейса и обновите файл службы. 