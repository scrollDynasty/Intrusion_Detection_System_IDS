cmake_minimum_required(VERSION 3.10)

project(Intrusion_Detection_System_IDS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Определяем операционную систему
if(WIN32)
    set(IS_WINDOWS TRUE)
    message(STATUS "Сборка для Windows")
else()
    set(IS_WINDOWS FALSE)
    message(STATUS "Сборка для Linux")
    # Добавляем определения для использования системных заголовков на Linux
    add_definitions(-DHAVE_NETINET_IP_H -DHAVE_NETINET_TCP_H)
endif()

# Проверяем несколько возможных путей к Qt
set(QT_POSSIBLE_PATHS
    "C:/Qt/6.8.2/msvc2019_64"
    "C:/Qt/6.8.2/mingw_64"
    "D:/Qt/6.8.2/msvc2019_64"
    "D:/Qt/6.8.2/mingw_64"
    "C:/Qt/6.8.2/msvc2022_64"
    "D:/Qt/6.8.2/msvc2022_64"
)

# Пытаемся найти Qt в возможных путях (только для Windows)
if(IS_WINDOWS)
    foreach(QT_PATH ${QT_POSSIBLE_PATHS})
        if(EXISTS "${QT_PATH}/lib/cmake/Qt6")
            list(APPEND CMAKE_PREFIX_PATH "${QT_PATH}")
            set(QT_BIN_DIR "${QT_PATH}/bin")
            message(STATUS "Found Qt at: ${QT_PATH}")
            break()
        endif()
    endforeach()
endif()

# Находим пакеты Qt (для Qt6)
find_package(Qt6 COMPONENTS Widgets Core REQUIRED)

# Проверяем наличие libpcap на Linux
if(NOT IS_WINDOWS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    message(STATUS "Found libpcap: ${PCAP_LIBRARIES}")
endif()

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
)

# Добавляем include директории в зависимости от платформы
if(IS_WINDOWS)
    include_directories(${CMAKE_SOURCE_DIR}/npcap/Include)
    link_directories(${CMAKE_SOURCE_DIR}/npcap/Lib/x64)
else()
    include_directories(${PCAP_INCLUDE_DIRS})
endif()

# Создаем обычный исполняемый файл без запроса прав администратора
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} ${UI_FILES} ${RESOURCES})

# Линкуем нужные библиотеки в зависимости от платформы
if(IS_WINDOWS)
    target_link_libraries(${PROJECT_NAME} PRIVATE
        Packet
        wpcap
        ws2_32
        iphlpapi
        Qt6::Widgets
    )
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE
        ${PCAP_LIBRARIES}
        Qt6::Widgets
    )
endif()

# Копируем необходимые DLL-файлы в директорию сборки
if(IS_WINDOWS)
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
