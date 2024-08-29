cmake_minimum_required(VERSION 3.10)

project(DataDistribution)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

if(NOT PCAP_FOUND)
    message(FATAL_ERROR "libpcap не найдена. Пожалуйста, установите libpcap-dev.")
endif()

include_directories(include)

set(SOURCE_FILES
    src/main.cc
    src/Packet.cc
    src/FirstHandler.cc
    src/SecondHandler.cc
    src/ThirdHandler.cc
)

add_executable(start_distribution ${SOURCE_FILES})

target_include_directories(start_distribution PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(start_distribution ${PCAP_LIBRARIES})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--strip-all")

