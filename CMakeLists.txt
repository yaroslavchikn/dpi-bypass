cmake_minimum_required(VERSION 3.10)
project(DpiBypass)

set(CMAKE_CXX_STANDARD 17)

if (WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

add_executable(dpi-bypass main.cpp)

target_link_libraries(dpi-bypass 
    ws2_32
    iphlpapi
)
