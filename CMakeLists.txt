cmake_minimum_required(VERSION 3.10)

project(Intrusion_Detection_System_IDS)

set(CMAKE_CXX_STANDARD 17)

set(SOURCES
        src/main.cpp
        src/PacketHandler.cpp
        src/DeviceManager.cpp
)

include_directories(
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/npcap/Include
)

link_directories(${CMAKE_SOURCE_DIR}/npcap/Lib/x64)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        Packet.lib
        wpcap.lib
        ws2_32.lib
)
