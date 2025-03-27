cmake_minimum_required(VERSION 3.10)

project(Intrusion_Detection_System_IDS)

set(CMAKE_CXX_STANDARD 17)

# Check operating system
if(WIN32)
    add_definitions(-DIS_WINDOWS)
else()
    add_definitions(-DHAVE_NETINET_IP_H -DHAVE_NETINET_TCP_H)
endif()

# Опция для сборки только SSH-версии (без GUI)
option(BUILD_SSH_ONLY "Build only SSH version without GUI" OFF)

# Найдём необходимые библиотеки
if(NOT BUILD_SSH_ONLY)
    # Для GUI-версии нужны Qt компоненты
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    
    # Define possible Qt installation paths for Windows
    if(WIN32)
        set(Qt6_INSTALL_PATHS
            "C:/Qt/6.5.2/msvc2019_64"
            "C:/Qt/6.5.1/msvc2019_64"
            "C:/Qt/6.5.0/msvc2019_64"
            "C:/Qt/6.4.3/msvc2019_64"
            "C:/Qt/6.4.2/msvc2019_64"
            "$ENV{QT_DIR}"
        )
        
        # Try to find Qt6 in the defined paths
        foreach(Qt6_PATH ${Qt6_INSTALL_PATHS})
            if(EXISTS "${Qt6_PATH}")
                list(APPEND CMAKE_PREFIX_PATH "${Qt6_PATH}")
                message(STATUS "Found Qt6 path: ${Qt6_PATH}")
                break()
            endif()
        endforeach()
    endif()
    
    # Qt пакеты только для GUI-версии
    find_package(Qt6 COMPONENTS Core Widgets Network REQUIRED)
endif()

# Find OpenSSL for SSH version
find_package(OpenSSL REQUIRED)

# Find libpcap for both versions
if(UNIX AND NOT APPLE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    include_directories(${PCAP_INCLUDE_DIRS})
    link_directories(${PCAP_LIBRARY_DIRS})
endif()

# Source files for SSH version (console only)
set(SSH_SOURCES
    src/main_ssh.cpp
    src/ServerCommandHandler.cpp
    src/SimplePacketHandler.cpp
    src/DeviceManagerConsole.cpp
    src/ServerSuspiciousIPModel.cpp
)

# Header files for SSH version
set(SSH_HEADERS
    include/ServerCommandHandler.h
    include/SimplePacketHandler.h
    include/DeviceManagerConsole.h
    include/ServerSuspiciousIPModel.h
)

# Add executable for SSH version (console only)
add_executable(${PROJECT_NAME}_SSH
    ${SSH_SOURCES}
    ${SSH_HEADERS}
)

# Set include directories for SSH version
target_include_directories(${PROJECT_NAME}_SSH PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link libraries for SSH version (console only)
if(WIN32)
    target_link_libraries(${PROJECT_NAME}_SSH PRIVATE
        wpcap
        Packet
        ws2_32
        IPHLPAPI
        ${OPENSSL_LIBRARIES}
    )
else()
    target_link_libraries(${PROJECT_NAME}_SSH PRIVATE
        ${PCAP_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        pthread
    )
endif()

# Только если не задана опция BUILD_SSH_ONLY, собираем GUI-версию
if(NOT BUILD_SSH_ONLY)
    # Source files for GUI version
    set(GUI_SOURCES
        src/main.cpp
        src/MainWindow.cpp
        src/PacketHandler.cpp
        src/DeviceManager.cpp
        src/SuspiciousIPModel.cpp
    )
    
    # Header files for GUI version
    set(GUI_HEADERS
        include/MainWindow.h
        include/PacketHandler.h
        include/DeviceManager.h
        include/SuspiciousIPModel.h
    )
    
    # Resource files (только для GUI-версии)
    set(RESOURCES
        resources.qrc
    )
    
    # Add executable for GUI version
    add_executable(${PROJECT_NAME}
        ${GUI_SOURCES}
        ${GUI_HEADERS}
        ${RESOURCES}
    )
    
    # Set include directories for GUI version
    target_include_directories(${PROJECT_NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    
    # Link libraries for GUI version
    if(WIN32)
        target_link_libraries(${PROJECT_NAME} PRIVATE
            Qt6::Core
            Qt6::Widgets
            Qt6::Network
            wpcap
            Packet
            ws2_32
            IPHLPAPI
        )
    else()
        target_link_libraries(${PROJECT_NAME} PRIVATE
            Qt6::Core
            Qt6::Widgets
            Qt6::Network
            ${PCAP_LIBRARIES}
        )
    endif()
    
    # For Windows, copy necessary DLLs to the build directory
    if(WIN32)
        # Copy Qt DLLs for the GUI version
        add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:Qt6::Core>
                $<TARGET_FILE:Qt6::Widgets>
                $<TARGET_FILE:Qt6::Network>
                $<TARGET_FILE_DIR:${PROJECT_NAME}>
        )
        
        # Copy Npcap DLLs for both versions
        foreach(TARGET ${PROJECT_NAME} ${PROJECT_NAME}_SSH)
            add_custom_command(TARGET ${TARGET} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${CMAKE_CURRENT_SOURCE_DIR}/libs/win32/wpcap.dll"
                    "${CMAKE_CURRENT_SOURCE_DIR}/libs/win32/Packet.dll"
                    $<TARGET_FILE_DIR:${TARGET}>
            )
        endforeach()
    endif()
endif()

# Copy OpenSSL DLLs for the SSH version (Windows)
if(WIN32)
    add_custom_command(TARGET ${PROJECT_NAME}_SSH POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_ROOT_DIR}/bin/libcrypto*.dll"
            "${OPENSSL_ROOT_DIR}/bin/libssl*.dll"
            $<TARGET_FILE_DIR:${PROJECT_NAME}_SSH>
    )
endif()

# Общие заголовочные файлы
set(HEADERS_COMMON
    include/PacketHandler.h
    include/SuspiciousIPModel.h
    include/DeviceManager.h
)

# Заголовочные файлы для GUI-версии
set(HEADERS_GUI
    include/MainWindow.h
    include/StatisticsDialog.h
    include/SettingsDialog.h
    include/AboutDialog.h
    include/LogViewerDialog.h
)

# Заголовочные файлы для SSH-версии
set(HEADERS_SSH
    include/ServerCommandHandler.h
    include/ServerSuspiciousIPModel.h
    include/DeviceManagerConsole.h
    include/SimplePacketHandler.h
    include/ConsoleLogEncryption.h
)
