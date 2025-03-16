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
        set(QT_BIN_DIR "${QT_PATH}/bin")
        message(STATUS "Found Qt at: ${QT_PATH}")
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
    include/ip_hdr.h
    include/tcp_hdr.h
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

# Создаем обычный исполняемый файл без запроса прав администратора
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} ${UI_FILES} ${RESOURCES})

target_link_libraries(${PROJECT_NAME}
    Packet
    wpcap
    ws2_32.lib
    Qt6::Widgets
    Qt6::Core
)

# Копируем необходимые DLL-файлы в директорию сборки
if(WIN32)
    # Копируем DLL-файлы Qt
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QT_BIN_DIR}/Qt6Core.dll"
            "${QT_BIN_DIR}/Qt6Gui.dll"
            "${QT_BIN_DIR}/Qt6Widgets.dll"
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
    )
    
    # Копируем плагины Qt
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms"
    )
    
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${QT_BIN_DIR}/../plugins/platforms/qwindows.dll"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>/plugins/platforms"
    )
    
    # Создаем файл qt.conf
    file(WRITE ${CMAKE_BINARY_DIR}/qt.conf "[Paths]\nPlugins=./plugins")
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_BINARY_DIR}/qt.conf"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
    )
    
    # Копируем DLL-файлы MinGW (если используется MinGW)
    if(QT_BIN_DIR MATCHES "mingw")
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${QT_BIN_DIR}/libgcc_s_seh-1.dll"
                "${QT_BIN_DIR}/libstdc++-6.dll"
                "${QT_BIN_DIR}/libwinpthread-1.dll"
                $<TARGET_FILE_DIR:${PROJECT_NAME}>
        )
    endif()
    
    # Копируем DLL-файлы Npcap
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "C:/Windows/System32/Packet.dll"
            "C:/Windows/System32/wpcap.dll"
            $<TARGET_FILE_DIR:${PROJECT_NAME}>
    )
endif()
