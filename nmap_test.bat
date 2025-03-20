@echo off
echo === Тестирование с помощью nmap ===
echo.

echo 1. TCP SYN сканирование (самое распространенное)
nmap -sS -p 80,443,8080,22,21 127.0.0.1
echo.

echo 2. TCP Connect сканирование
nmap -sT -p 80,443,8080,22,21 127.0.0.1
echo.

echo 3. UDP сканирование
nmap -sU -p 53,123,161,1900 127.0.0.1
echo.

echo 4. Ping сканирование
nmap -sn 127.0.0.1
echo.

echo Тестирование завершено!
pause 