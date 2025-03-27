# 🛡️ Intrusion Detection System (IDS)

<div align="center">

![Version](https://img.shields.io/badge/Версия-3.2.0-blue?style=for-the-badge)
![Qt](https://img.shields.io/badge/Qt-6.8.2-green?style=for-the-badge&logo=qt)
![C++](https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=cplusplus)
![Docker](https://img.shields.io/badge/Docker-Поддерживается-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/Лицензия-MIT-yellow?style=for-the-badge)

</div>

## 📖 Обзор

**Intrusion Detection System (IDS)** — это система обнаружения вторжений с графическим интерфейсом, разработанная на C++ с использованием Qt. Система мониторит входящие и исходящие сетевые пакеты в реальном времени, обнаруживает и регистрирует подозрительную активность, такую как TCP SYN-пакеты, которые часто указывают на сканирование портов или DoS-атаки.

## 🚀 Быстрый старт

### ⚡ Готовый исполняемый файл

Для быстрого начала работы вы можете скачать готовый исполняемый файл из [раздела релизов](https://github.com/scrollDynasty/Intrusion_Detection_System_IDS/releases). Просто распакуйте архив и запустите `Intrusion_Detection_System_IDS.exe` — никаких дополнительных установок не требуется!

> **Примечание:** Готовый исполняемый файл содержит все необходимые библиотеки и может быть запущен на любом компьютере с Windows без установки Qt или других зависимостей.

### 🔧 Настройка для обнаружения сканирования портов с других компьютеров

Для корректного обнаружения сканирования портов и других атак с других компьютеров в сети необходимо:

1. **Запустить программу от имени администратора** — это необходимо для работы в режиме promiscuous
2. **Установить Npcap** — скачайте и установите [Npcap](https://nmap.org/npcap/) с официального сайта
   - При установке выберите опцию 'Install Npcap in WinPcap API-compatible Mode'
   - Перезагрузите компьютер после установки
3. **Выбрать правильный сетевой адаптер** — используйте физический сетевой адаптер, а не виртуальный
   - Убедитесь, что выбранный адаптер поддерживает режим promiscuous
   - Для Wi-Fi адаптеров может потребоваться включение режима мониторинга в настройках драйвера
4. **Проверить настройки сети** — некоторые сетевые коммутаторы могут блокировать режим promiscuous
   - В корпоративных сетях может потребоваться настройка порта коммутатора для работы в режиме зеркалирования (port mirroring)

> **Важно:** Если вы не видите пакеты с других компьютеров в сети, проверьте, что все вышеперечисленные условия выполнены.

### 📡 Режим Promiscuous и ограничения сетевых коммутаторов

#### Что такое режим Promiscuous?
Режим Promiscuous позволяет сетевому адаптеру захватывать все пакеты в сети, а не только те, которые адресованы непосредственно этому компьютеру. Это необходимо для обнаружения сканирования портов и других атак с других компьютеров в сети.

#### Ограничения сетевых коммутаторов
В современных сетях с коммутаторами (switches) существуют ограничения на видимость пакетов:

1. **Коммутаторы vs. Хабы:** 
   - **Хабы (устаревшие)** отправляют все пакеты на все порты, что позволяет видеть весь трафик
   - **Коммутаторы (современные)** отправляют пакеты только на порт назначения, что ограничивает видимость

2. **Решения для работы с коммутаторами:**
   - **Port Mirroring (SPAN)** — настройка коммутатора для копирования трафика с одного порта на другой
   - **Network TAP** — специальное устройство для перехвата сетевого трафика
   - **ARP Spoofing** — техника перенаправления трафика (не рекомендуется в производственных сетях)

3. **Домашние сети:**
   - В домашних сетях с Wi-Fi роутерами обычно трудно увидеть трафик других устройств
   - Для тестирования можно использовать тестовый режим программы

> **Рекомендация:** Если вам нужно обнаруживать атаки в реальной сети, рассмотрите возможность установки IDS на пограничном устройстве (например, на маршрутизаторе) или настройте port mirroring на коммутаторе.

## ✨ Новые функции и улучшения в версии 3.2.0

### 🔄 Единый лаунчер для выбора режима запуска
- **Выбор режима при запуске** — удобный интерфейс для выбора между GUI и SSH режимами
- **Унифицированный скрипт запуска** — единый скрипт `launcher.sh` для запуска любой версии
- **Совместимость режимов** — полная совместимость логов между режимами
- **Скрипт сборки всех версий** — добавлен `build_all.sh` для одновременной сборки GUI и SSH версий

### 🔐 Улучшенная работа с шифрованием в SSH-режиме
- **Интерактивный ввод пароля** — запрос пароля при дешифровании в SSH-режиме
- **Скрытый ввод пароля** — отключение эхо-вывода для безопасного ввода пароля в терминале
- **Повторные попытки ввода** — возможность повторить ввод пароля при неудачном дешифровании
- **Автоматические подсказки** — улучшенные подсказки и сообщения об ошибках шифрования

### 🛠️ Технические улучшения
- **Обновление до OpenSSL 3.0** — использование современного API OpenSSL для шифрования
- **Устранение предупреждений** — исправления для предупреждений компилятора
- **Улучшенное отображение подозрительных IP** — автоматическая прокрутка к новым записям
- **Выделение новых записей** — автоматическое выделение новых подозрительных IP для привлечения внимания

## ✨ Новые функции и улучшения в версии 3.1.3

### 🐧 Официальная поддержка Linux
- **Полная поддержка Linux** — система теперь официально работает на дистрибутивах Linux
- **Адаптированные скрипты** — добавлены специальные скрипты для сборки и запуска в Linux
- **Автоматическое определение сетевых интерфейсов** — корректная работа с различными типами интерфейсов в Linux
- **Совместимость с libpcap** — оптимизирована работа с Linux-версией библиотеки захвата пакетов
- **Скрипты установки зависимостей** — упрощенная установка необходимых компонентов для Linux

### 🛠️ Технические улучшения
- **Кроссплатформенная компиляция** — улучшенная совместимость исходного кода между Windows и Linux
- **Расширенная документация** — добавлены детальные инструкции для запуска на Linux
- **Исправления для Linux** — адаптация типов данных и интерфейсов для корректной работы в Linux
- **Улучшенный CMake** — обновленные инструкции сборки для различных платформ

## ✨ Новые функции и улучшения в версии 3.1.2

### 🐛 Исправления и улучшения интерфейса
- **Улучшена поддержка кириллических символов** — исправлена кодировка UTF-8 во всех формах и сообщениях
- **Перевод интерфейса на русский язык** — все диалоговые окна и кнопки теперь корректно отображаются на русском
- **Добавлено диалоговое окно "О программе"** — реализован информационный диалог с данными о версии и функциях
- **Усовершенствована система сохранения логов** — добавлен запрос на сохранение при выходе из программы
- **Улучшена работа с зашифрованными логами** — оптимизирована работа с .enc файлами и механизм проверки пароля

## ✨ Новые функции и улучшения в версии 3.1.1

### 🐛 Исправления багов
- **Исправлена проблема с отображением текста ошибок** — теперь сообщения об ошибках корректно отображаются на всех компьютерах
- **Улучшена поддержка кодировки UTF-8** — добавлена явная установка кодировки во всех .bat файлах и в коде приложения
- **Исправлено отображение текста в окне отладки** — теперь текст корректно отображается с использованием UTF-8
- **Улучшен интерфейс диалоговых окон** — увеличен размер окон сообщений для лучшей читаемости
- **Оптимизирована работа с файлами логов** — добавлена явная установка кодировки UTF-8 для файлов логов

## ✨ Функции и улучшения в версии 3.1.0

### 🔍 Улучшенное обнаружение внешних угроз
- **Режим Promiscuous** — улучшена поддержка режима захвата всех пакетов в сети
- **Обнаружение внешних сканирований** — система теперь может обнаруживать сканирование портов с других компьютеров в сети
- **Определение локальных и внешних IP** — автоматическое определение локальных IP-адресов для точного обнаружения внешних угроз
- **Расширенная отладочная информация** — подробное логирование для диагностики проблем с захватом пакетов
- **Улучшенная обработка TCP пакетов** — более точное обнаружение сканирования портов и других атак

### 🛠️ Технические улучшения
- **Оптимизация захвата пакетов** — увеличен таймаут для лучшего захвата пакетов в сети
- **Проверка поддержки режима Promiscuous** — автоматическая проверка возможностей сетевого адаптера
- **Подробная документация** — добавлена информация о настройке системы для обнаружения внешних угроз
- **Улучшенные сообщения об ошибках** — более информативные сообщения при возникновении проблем
- **Совместимость с различными сетевыми адаптерами** — улучшена поддержка различных типов сетевых адаптеров

## ✨ Функции и улучшения в версии 3.0.0

### 🎨 Современный пользовательский интерфейс
- **Темная тема** — улучшенная читаемость и снижение нагрузки на глаза
- **Цветовая индикация угроз** — визуальное выделение подозрительных IP-адресов:
  - 🔴 **Красный** — критический уровень (более 20 пакетов)
  - 🟠 **Оранжевый** — высокий уровень (более 10 пакетов)
  - 🟡 **Желтый** — средний уровень (более 5 пакетов)
- **Индикатор статуса** — визуальное отображение активности захвата пакетов
- **Всплывающие подсказки** — детальная информация о записях при наведении курсора
- **Автоматическое изменение размеров колонок** — улучшенное отображение данных в таблицах
- **HTML-форматирование логов** — цветовое выделение подозрительных пакетов в логе

### 🔍 Улучшенное обнаружение вторжений
- **Расширенная классификация пакетов** — более точное определение типов пакетов (TCP SYN, TCP ACK, TCP FIN, TCP RST, UDP, ICMP)
- **Улучшенный анализ трафика** — обнаружение аномалий в сетевом трафике
- **Подробное логирование** — HTML-форматирование логов с цветовой индикацией типов пакетов
- **Обнаружение сканирования портов** — анализ TCP SYN пакетов на привилегированные порты (< 1024)
- **Обнаружение попыток подключения к уязвимым сервисам** — мониторинг подключений к SMB, RDP, SSH, Telnet, MS SQL, MySQL
- **Обнаружение UDP и ICMP флуда** — анализ частоты пакетов на известные порты

### 🧪 Тестовый режим
- **Генерация тестового трафика** — возможность тестирования функциональности без реального сетевого трафика
- **Тестовый адаптер** — специальный режим работы без необходимости прав администратора
- **Различные типы тестовых пакетов** — генерация TCP, UDP и ICMP пакетов с различными параметрами
- **Симуляция угроз** — генерация подозрительных пакетов для тестирования системы обнаружения

### 🛡️ Повышенная стабильность
- **Обработка исключений** — предотвращение сбоев приложения при возникновении ошибок
- **Улучшенная обработка ошибок** — информативные сообщения об ошибках в логах
- **Безопасное завершение захвата** — корректное освобождение ресурсов при остановке захвата
- **Счетчики пакетов** — отображение количества обнаруженных и подозрительных пакетов в статусной строке

### 🐳 Поддержка Docker
- **Кросс-платформенность** — запуск на Linux, Windows и macOS без установки зависимостей
- **Простота развертывания** — автоматизированные скрипты для запуска на разных платформах
- **Изоляция окружения** — работа в изолированном контейнере для повышения безопасности

### 📦 Портативность
- **Автономный режим** — работа без установки дополнительных библиотек
- **Скрипт развертывания** — автоматическое создание портативной версии приложения
- **Совместимость** — работа на различных версиях Windows без дополнительных настроек

## 📸 Скриншоты

<div align="center">
  <img src="img/image.png" alt="Главное окно приложения" width="800"/>
  <p><em>Главное окно приложения с темной темой и мониторингом сетевой активности</em></p>
  
  <img src="img/orange.png" alt="Анализ пакетов" width="800"/>
  <p><em>Анализ подозрительных пакетов с цветовой индикацией уровней угрозы</em></p>
  
  <img src="img/scan.png" alt="Обнаружение угроз" width="800"/>
  <p><em>Обнаружение и классификация сетевых угроз в реальном времени</em></p>
</div>

## 🚀 Установка и запуск

### Новый унифицированный способ (рекомендуется)
1. Соберите обе версии (GUI и SSH) одной командой:
```bash
chmod +x build_all.sh
./build_all.sh
```

2. Запустите программу через лаунчер и выберите нужный режим:
```bash
./launcher.sh
```

### 🪟 Windows

#### Вариант 1: Использование готового исполняемого файла (рекомендуется)
1. Скачайте последний релиз из [раздела релизов](https://github.com/scrollDynasty/Intrusion_Detection_System_IDS/releases)
2. Распакуйте архив в любую директорию
3. Запустите `Intrusion_Detection_System_IDS.exe`

#### Вариант 2: Сборка из исходного кода
1. Установите [Qt 6.8.2](https://www.qt.io/download)
2. Установите [CMake](https://cmake.org/download/)
3. Установите [MinGW](https://www.mingw-w64.org/downloads/) или [Visual Studio](https://visualstudio.microsoft.com/downloads/)
4. Установите [Npcap](https://nmap.org/npcap/) (обязательно выберите опцию "Install Npcap in WinPcap API-compatible Mode")
5. Клонируйте репозиторий и соберите проект:
```cmd
:: Клонирование репозитория
git clone https://github.com/scrollDynasty/Intrusion_Detection_System_IDS.git
cd Intrusion_Detection_System_IDS

:: Сборка проекта с MinGW
mkdir cmake-build-debug
cd cmake-build-debug
cmake .. -G "MinGW Makefiles"
cmake --build .

:: Создание портативной версии
cd ..
.\deploy.bat

:: Запуск приложения
.\deploy\Intrusion_Detection_System_IDS.exe
```

#### Вариант 3: Запуск через Docker
1. Установите [Docker Desktop для Windows](https://www.docker.com/products/docker-desktop)
2. Установите [VcXsrv Windows X Server](https://sourceforge.net/projects/vcxsrv/)
3. Запустите скрипт `run_docker.bat`

### 🐧 Linux

#### Вариант 1: Использование унифицированного лаунчера
```bash
# Сборка всех версий
chmod +x build_all.sh
./build_all.sh

# Запуск лаунчера
./launcher.sh
```

#### Вариант 2: Ручная сборка и запуск
```bash
# Клонирование репозитория
git clone https://github.com/scrollDynasty/Intrusion_Detection_System_IDS.git
cd Intrusion_Detection_System_IDS

# Сборка проекта
mkdir -p build
cd build
cmake ..
make -j$(nproc)

# Запуск приложения (требуются права root)
sudo ./Intrusion_Detection_System_IDS
```

#### Вариант 3: Запуск через Docker
```bash
# Установка Docker и docker-compose
sudo apt-get install -y docker.io docker-compose
sudo usermod -aG docker $USER  # Требуется перезагрузка или выход/вход в систему

# Запуск приложения
chmod +x run_docker.sh
./run_docker.sh
```

### 🍎 macOS

#### Установка зависимостей
```bash
# Установка Homebrew (если не установлен)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Установка Qt и других зависимостей
brew install cmake qt@6 libpcap

# Добавление Qt в PATH
echo 'export PATH="/usr/local/opt/qt@6/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

#### Сборка из исходного кода
```bash
# Клонирование репозитория
git clone https://github.com/scrollDynasty/Intrusion_Detection_System_IDS.git
cd Intrusion_Detection_System_IDS

# Сборка проекта
mkdir -p cmake-build-debug
cd cmake-build-debug
cmake ..
cmake --build .

# Запуск приложения
./Intrusion_Detection_System_IDS
```

#### Запуск через Docker
```bash
# Установка Docker Desktop для Mac
brew install --cask docker

# Установка XQuartz
brew install --cask xquartz

# Запуск приложения
chmod +x run_docker_mac.sh
./run_docker_mac.sh
```

## 📦 Создание портативной версии

Для создания портативной версии приложения, которую можно запускать на любом компьютере с Windows без установки дополнительных библиотек, используйте скрипт `deploy.bat`:

```cmd
:: Запуск скрипта развертывания
.\deploy.bat
```

Скрипт создаст директорию `deploy` со всеми необходимыми файлами. Вы можете архивировать эту директорию и распространять её как портативную версию приложения.

## 🐳 Docker: подробное руководство

### Преимущества использования Docker
- **Единое окружение** — одинаковая среда выполнения на всех платформах
- **Отсутствие конфликтов зависимостей** — изолированное окружение для приложения
- **Простота развертывания** — не требуется установка Qt и других библиотек

### Структура Docker-файлов
- **Dockerfile** — основной файл для создания образа
- **docker-compose.yml** — конфигурация для запуска контейнера
- **run_docker.sh** — скрипт запуска для Linux
- **run_docker.bat** — скрипт запуска для Windows
- **run_docker_mac.sh** — скрипт запуска для macOS

### Запуск на разных платформах

#### Linux
```bash
# Разрешение выполнения скрипта
chmod +x run_docker.sh

# Запуск
./run_docker.sh
```

#### Windows
```cmd
:: Запуск из командной строки
run_docker.bat

:: Или двойным щелчком по файлу run_docker.bat
```

#### macOS
```bash
# Разрешение выполнения скрипта
chmod +x run_docker_mac.sh

# Запуск
./run_docker_mac.sh
```

### Возможные проблемы и их решение

#### Проблемы с отображением GUI
- **Linux**: Убедитесь, что вы разрешили доступ к X-серверу: `xhost +local:docker`
- **Windows**: Проверьте, что VcXsrv запущен с параметрами `-multiwindow -clipboard -wgl`
- **macOS**: Убедитесь, что XQuartz запущен и разрешены подключения: `xhost +localhost`

#### Проблемы с доступом к сетевым интерфейсам
- Для работы с сетевыми интерфейсами контейнер должен быть запущен с привилегированным доступом (`privileged: true` в docker-compose.yml)
- На Windows может потребоваться запуск Docker Desktop от имени администратора

## 💻 Использование приложения

### Выбор режима запуска
При запуске с помощью `launcher.sh` вы можете выбрать режим работы программы:
1. **GUI-режим** — графический интерфейс с визуализацией и таблицами
2. **SSH-режим** — консольный интерфейс для работы через терминал
3. **Выход** — завершение работы программы

### Работа с шифрованием в SSH-режиме
В SSH-режиме теперь доступны следующие улучшенные функции:
1. **Установка пароля шифрования** — команда `encrypt [password]`
2. **Дешифрование логов** — команда `decrypt [filename]`
   - При отсутствии пароля будет запрошен ввод пароля в интерактивном режиме
   - Ввод пароля происходит в скрытом режиме (без отображения символов)
   - При неверном пароле предлагается повторить попытку

### Основные функции
1. **Выбор сетевого интерфейса** — выберите интерфейс для мониторинга из списка доступных
2. **Запуск/остановка захвата пакетов** — управление процессом мониторинга
3. **Просмотр подозрительных IP-адресов** — таблица с информацией о подозрительной активности
4. **Просмотр логов** — детальная информация о захваченных пакетах

### Интерпретация результатов
- **Цветовая индикация** — помогает быстро идентифицировать уровень угрозы
- **Счетчик пакетов** — показывает количество пакетов от конкретного IP-адреса
- **Временные метки** — время обнаружения подозрительной активности
- **Типы пакетов** — классификация пакетов по типу (SYN, ACK, FIN и т.д.)

## 🛠️ Технические детали

### Архитектура приложения
- **Модуль захвата пакетов** — использует libpcap/Npcap для захвата сетевого трафика
- **Модуль анализа** — обрабатывает захваченные пакеты и выявляет подозрительную активность
- **Модуль визуализации** — отображает результаты анализа в удобном для пользователя виде
- **Модуль логирования** — сохраняет информацию о захваченных пакетах и обнаруженных угрозах

### Используемые технологии
- **C++17** — основной язык программирования
- **Qt 6.8.2** — фреймворк для создания графического интерфейса
- **libpcap/Npcap** — библиотека для захвата сетевых пакетов
- **CMake** — система сборки
- **Docker** — контейнеризация приложения

## 🔮 Планы на будущее

- [ ] **Расширенная аналитика** — добавление статистики и графиков для анализа трафика
- [ ] **Система оповещений** — уведомления о подозрительной активности
- [ ] **Экспорт данных** — возможность экспорта результатов анализа в различные форматы
- [ ] **Профили мониторинга** — создание и сохранение различных профилей для мониторинга
- [ ] **Интеграция с базами данных угроз** — проверка IP-адресов по базам известных угроз

## 🧪 Тестирование программы

Для проверки работоспособности системы и обнаружения различных типов атак вы можете использовать включенные в дистрибутив скрипты и утилиты.

### 📊 Проверка с помощью Python-скрипта для DOS-атак

1. **Запустите IDS** и выберите сетевой интерфейс для мониторинга
2. **Откройте командную строку** от имени администратора
3. **Запустите Python-скрипт для DOS-атаки** с параметрами:

```bash
# Для TCP атаки
python dos_attack.py -t 127.0.0.1 -p 80 -m tcp -d 10 -c 100

# Для UDP атаки
python dos_attack.py -t 127.0.0.1 -p 53 -m udp -d 10 -c 50

# Для ICMP (ping) атаки
python dos_attack.py -t 127.0.0.1 -m icmp -d 10 -c 50
```

Где:
- `-t` (--target): целевой IP-адрес
- `-p` (--port): целевой порт (не требуется для ICMP)
- `-m` (--mode): режим атаки (tcp, udp, icmp)
- `-d` (--duration): продолжительность в секундах
- `-c` (--connections): количество одновременных соединений

**Результат**: IDS должна обнаружить и отобразить подозрительную активность в таблице подозрительных IP и журнале событий.

### 🔍 Проверка с помощью Nmap

1. **Запустите IDS** и выберите сетевой интерфейс для мониторинга
2. **Запустите скрипт тестирования** с помощью Nmap:

```bash
# Используя BAT файл
test_scan.bat

# Или напрямую с помощью Nmap
nmap -sS -p 1-1000 127.0.0.1
```

**Результат**: IDS должна обнаружить серию TCP SYN пакетов, распознать их как сканирование портов и отобразить в таблице подозрительных IP.

### 🔄 Интерпретация результатов тестирования

При успешном тестировании вы должны увидеть:
1. **Увеличение счетчика пакетов** в статусной строке
2. **Появление новых записей** в таблице подозрительных IP
3. **Предупреждающие сообщения** в журнале событий
4. **Цветовую индикацию** угроз в зависимости от количества обнаруженных пакетов

Если какой-либо из тестов не дает ожидаемых результатов, проверьте:
- Правильно ли выбран сетевой интерфейс
- Запущена ли программа с правами администратора
- Включен ли режим promiscuous
- Не блокирует ли антивирус или брандмауэр сетевую активность

## 📜 Лицензия

Этот проект распространяется под лицензией **MIT**. Подробности смотрите в файле [LICENSE](LICENSE).

## 💬 Контакты

Есть вопросы или предложения? Свяжитесь с нами!

- **Email**: ymarumar502@gmail.com
- **GitHub**: [scrollDynasty](https://github.com/scrollDynasty)

---

<div align="center">
  <p>Разработал scrollDynasty</p>
  <p>© 2024-2025 Intrusion Detection System</p>
</div>

## 📋 Особенности работы на Linux

### 🔧 Требования для захвата пакетов
- **Права суперпользователя (root)** — обязательно для перехвата сетевого трафика
- **Установленный libpcap** — основная библиотека для захвата пакетов
- **X11 сервер** — для запуска графического интерфейса (предустановлен в большинстве дистрибутивов)

### 🛡️ Возможные проблемы и их решения
- **Нет доступа к сетевым адаптерам**:
  ```bash
  # Проверка наличия пользователя в группе, имеющей доступ к сетевым устройствам
  sudo usermod -a -G wireshark $USER
  # Перезагрузка системы или перелогин пользователя
  ```

- **Ошибка загрузки libpcap**:
  ```bash
  # Проверка установки libpcap
  ldconfig -p | grep pcap
  # Установка libpcap, если отсутствует
  sudo apt install libpcap-dev  # Для Debian/Ubuntu
  ```

- **Проблемы с отображением Qt интерфейса**:
  ```bash
  # Проверка установки необходимых библиотек Qt
  sudo apt install libqt6widgets6 libqt6gui6 libqt6core6
  ```

### 🔍 Дополнительные возможности в Linux
- **Улучшенный доступ к низкоуровневому сетевому API** — более точный анализ пакетов
- **Автоматическое определение всех сетевых интерфейсов** — включая виртуальные интерфейсы
- **Поддержка широкого спектра сетевых устройств** — включая промышленные сетевые адаптеры
- **Работа с контейнерами Docker** — возможность запуска в изолированной среде
