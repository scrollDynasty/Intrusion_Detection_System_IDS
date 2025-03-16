@echo off
echo Запуск Intrusion Detection System в Docker

REM Проверка наличия Docker
where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo Docker не установлен. Пожалуйста, установите Docker Desktop для Windows.
    pause
    exit /b 1
)

REM Проверка наличия X-сервера (VcXsrv)
where vcxsrv >nul 2>nul
if %errorlevel% neq 0 (
    echo X-сервер не найден. Пожалуйста, установите VcXsrv Windows X Server.
    echo Скачать можно здесь: https://sourceforge.net/projects/vcxsrv/
    pause
    exit /b 1
)

REM Запуск X-сервера, если он еще не запущен
tasklist | find /i "vcxsrv.exe" >nul 2>nul
if %errorlevel% neq 0 (
    echo Запуск X-сервера...
    start "" "C:\Program Files\VcXsrv\vcxsrv.exe" -multiwindow -clipboard -wgl
    timeout /t 2 >nul
)

REM Установка переменной DISPLAY
set DISPLAY=host.docker.internal:0.0

REM Сборка и запуск контейнера
echo Сборка и запуск Docker-контейнера...
docker-compose up --build

echo.
echo Готово!
pause 