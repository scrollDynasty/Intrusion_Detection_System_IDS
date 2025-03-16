cmake_minimum_required(VERSION 3.10)

project(Intrusion_Detection_System_IDS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Проверяем несколько возможных путей к Qt
set(QT_POSSIBLE_PATHS
    "C:/Qt/6.8.2/msvc2019_64"
    "C:/Qt/6.8.2/mingw_64"
    "D:/Qt/6.8.2/msvc2019_64"
    "D:/Qt/6.8.2/mingw_64"
    "C:/Qt/6.8.2/msvc2022_64"
    "D:/Qt/6.8.2/msvc2022_64"
)

# Пытаемся найти Qt в возможных путях
foreach(QT_PATH ${QT_POSSIBLE_PATHS})
    if(EXISTS "${QT_PATH}/lib/cmake/Qt6")
        list(APPEND CMAKE_PREFIX_PATH "${QT_PATH}")
        break()
    endif()
endforeach()

# Находим пакеты Qt (для Qt6)
find_package(Qt6 COMPONENTS Widgets Core REQUIRED)

set(SOURCES
        src/main.cpp
        src/PacketHandler.cpp
        src/DeviceManager.cpp
        src/MainWindow.cpp
        src/SuspiciousIPModel.cpp
)

set(HEADERS
        include/PacketHandler.h
        include/DeviceManager.h
        include/MainWindow.h
        include/SuspiciousIPModel.h
)

set(UI_FILES
        src/MainWindow.ui
)

# Добавляем файл ресурсов
set(RESOURCES
        resources.qrc
)

include_directories(
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/npcap/Include
)

link_directories(${CMAKE_SOURCE_DIR}/npcap/Lib/x64)

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} ${UI_FILES} ${RESOURCES})

target_link_libraries(${PROJECT_NAME}
        Packet.lib
        wpcap.lib
        ws2_32.lib
        Qt6::Widgets
        Qt6::Core
)
