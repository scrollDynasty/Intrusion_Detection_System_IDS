@echo off
chcp 65001 > null
echo Deploying Intrusion Detection System...

REM Создаем директорию для развертывания
mkdir deploy 2>nul

REM Копируем исполняемый файл
copy cmake-build-debug\Intrusion_Detection_System_IDS.exe deploy\

REM Копируем DLL-файлы Npcap
copy C:\Windows\System32\Packet.dll deploy\
copy C:\Windows\System32\wpcap.dll deploy\

REM Определяем путь к Qt
for %%Q in (
    "C:\Qt\6.8.2\mingw_64"
    "D:\Qt\6.8.2\mingw_64"
    "C:\Qt\6.8.2\msvc2019_64"
    "D:\Qt\6.8.2\msvc2019_64"
    "C:\Qt\6.8.2\msvc2022_64"
    "D:\Qt\6.8.2\msvc2022_64"
) do (
    if exist "%%~Q\bin\Qt6Core.dll" (
        set QT_DIR=%%~Q
        goto :found_qt
    )
)

echo Qt not found!
exit /b 1

:found_qt
echo Found Qt at %QT_DIR%

REM Копируем DLL-файлы Qt
copy "%QT_DIR%\bin\Qt6Core.dll" deploy\
copy "%QT_DIR%\bin\Qt6Gui.dll" deploy\
copy "%QT_DIR%\bin\Qt6Widgets.dll" deploy\

REM Создаем директорию для плагинов
mkdir deploy\plugins\platforms 2>nul
copy "%QT_DIR%\plugins\platforms\qwindows.dll" deploy\plugins\platforms\

REM Создаем файл qt.conf
echo [Paths] > deploy\qt.conf
echo Plugins=./plugins >> deploy\qt.conf

REM Если используется MinGW, копируем его DLL-файлы
if exist "%QT_DIR%\bin\libgcc_s_seh-1.dll" (
    copy "%QT_DIR%\bin\libgcc_s_seh-1.dll" deploy\
    copy "%QT_DIR%\bin\libstdc++-6.dll" deploy\
    copy "%QT_DIR%\bin\libwinpthread-1.dll" deploy\
)

echo Deployment completed successfully!
echo All files are in the 'deploy' directory. 