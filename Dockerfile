FROM ubuntu:22.04

# Установка необходимых пакетов
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libpcap-dev \
    qt6-base-dev \
    libqt6widgets6 \
    libqt6gui6 \
    libqt6core6 \
    libqt6network6 \
    libqt6svg6 \
    libqt6concurrent6 \
    libxcb-cursor0 \
    libxcb-xinerama0 \
    libxcb-xkb1 \
    libxkbcommon-x11-0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxcb-util1 \
    libxcb-xinput0 \
    libxcb1 \
    x11-apps \
    && rm -rf /var/lib/apt/lists/*

# Создание рабочей директории
WORKDIR /app

# Копирование исходного кода
COPY . /app/

# Создание директории для сборки
RUN mkdir -p cmake-build-debug

# Сборка проекта
WORKDIR /app/cmake-build-debug
RUN cmake .. && cmake --build .

# Создание скрипта запуска
RUN echo '#!/bin/bash\n\
cd /app/cmake-build-debug\n\
./Intrusion_Detection_System_IDS "$@"' > /app/start.sh && \
    chmod +x /app/start.sh

# Установка точки входа
ENTRYPOINT ["/app/start.sh"] 