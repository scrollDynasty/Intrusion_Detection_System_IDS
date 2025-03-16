# 🛡️ Intrusion Detection System (IDS)

<div align="center">

![Version](https://img.shields.io/badge/Версия-2.0.0-blue?style=for-the-badge)
![Qt](https://img.shields.io/badge/Qt-6.x-green?style=for-the-badge&logo=qt)
![C++](https://img.shields.io/badge/C++-17-00599C?style=for-the-badge&logo=cplusplus)
![Docker](https://img.shields.io/badge/Docker-Поддерживается-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/Лицензия-MIT-yellow?style=for-the-badge)

</div>

<p align="center">
  <img src="img/ids_logo.png" alt="IDS Logo" width="300"/>
</p>

## 📖 Обзор

**Intrusion Detection System (IDS)** — это система обнаружения вторжений с графическим интерфейсом, разработанная на C++ с использованием Qt. Система мониторит входящие и исходящие сетевые пакеты в реальном времени, обнаруживает и регистрирует подозрительную активность, такую как TCP SYN-пакеты, которые часто указывают на сканирование портов или DoS-атаки.

## ✨ Новые функции и улучшения

### 🎨 Современный пользовательский интерфейс
- **Темная тема** — улучшенная читаемость и снижение нагрузки на глаза192.168.100.43
- **Цветовая индикация угроз** — визуальное выделение подозрительных IP-адресов:
  - 🔴 **Красный** — критический уровень (более 20 пакетов)
  - 🟠 **Оранжевый** — высокий уровень (более 10 пакетов)
  - 🟡 **Желтый** — средний уровень (более 5 пакетов)
- **Индикатор статуса** — визуальное отображение активности захвата пакетов
- **Всплывающие подсказки** — детальная информация о записях при наведении курсора

### 🔍 Улучшенное обнаружение вторжений
- **Расширенная классификация пакетов** — более точное определение типов пакетов
- **Улучшенный анализ трафика** — обнаружение аномалий в сетевом трафике
- **Подробное логирование** — HTML-форматирование логов с цветовой индикацией типов пакетов

### 🐳 Поддержка Docker
- **Кросс-платформенность** — запуск на Linux, Windows и macOS без установки зависимостей
- **Простота развертывания** — автоматизированные скрипты для запуска на разных платформах
- **Изоляция окружения** — работа в изолированном контейнере для повышения безопасности

## 📸 Скриншоты

<div align="center">
  <img src="img/screenshot1.png" alt="Главный экран" width="400"/>
  <p><em>Главный экран с темной темой и индикацией подозрительных IP-адресов</em></p>
  
  <img src="img/screenshot2.png" alt="Обнаружение пакетов" width="400"/>
  <p><em>Обнаружение и анализ подозрительных пакетов в реальном времени</em></p>
</div>

## 🚀 Установка и запуск

### 🐧 Linux

#### Установка зависимостей
```bash
# Установка Qt и других зависимостей
sudo apt-get update
sudo apt-get install -y build-essential cmake libpcap-dev qt6-base-dev libqt6widgets6 libqt6gui6 libqt6core6 libqt6network6
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
# Установка Docker и docker-compose
sudo apt-get install -y docker.io docker-compose
sudo usermod -aG docker $USER  # Требуется перезагрузка или выход/вход в систему

# Запуск приложения
chmod +x run_docker.sh
./run_docker.sh
```

### 🪟 Windows

#### Установка зависимостей
1. Установите [Qt 6.x](https://www.qt.io/download)
2. Установите [CMake](https://cmake.org/download/)
3. Установите [MinGW](https://www.mingw-w64.org/downloads/) или [Visual Studio](https://visualstudio.microsoft.com/downloads/)
4. Установите [Npcap](https://nmap.org/npcap/) или [WinPcap](https://www.winpcap.org/install/)

#### Сборка из исходного кода
```cmd
:: Клонирование репозитория
git clone https://github.com/scrollDynasty/Intrusion_Detection_System_IDS.git
cd Intrusion_Detection_System_IDS

:: Сборка проекта с MinGW
mkdir cmake-build-debug
cd cmake-build-debug
cmake .. -G "MinGW Makefiles"
cmake --build .

:: Запуск приложения
Intrusion_Detection_System_IDS.exe
```

#### Запуск через Docker
1. Установите [Docker Desktop для Windows](https://www.docker.com/products/docker-desktop)
2. Установите [VcXsrv Windows X Server](https://sourceforge.net/projects/vcxsrv/)
3. Запустите скрипт `run_docker.bat`

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
- **Qt 6.x** — фреймворк для создания графического интерфейса
- **libpcap/Npcap** — библиотека для захвата сетевых пакетов
- **CMake** — система сборки
- **Docker** — контейнеризация приложения

## 🔮 Планы на будущее

- [ ] **Расширенная аналитика** — добавление статистики и графиков для анализа трафика
- [ ] **Система оповещений** — уведомления о подозрительной активности
- [ ] **Экспорт данных** — возможность экспорта результатов анализа в различные форматы
- [ ] **Профили мониторинга** — создание и сохранение различных профилей для мониторинга
- [ ] **Интеграция с базами данных угроз** — проверка IP-адресов по базам известных угроз

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