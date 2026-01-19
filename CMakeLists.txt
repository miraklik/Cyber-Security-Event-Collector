cmake_minimum_required(VERSION 3.20)
project(CyberSecServer)

set(CMAKE_CXX_STANDARD, 23)
include_directories(/opt/homebrew/include)
    
add_executable(security_server main.cpp)

find_package(Threads REQUIRED)
target_link_libraries(security_server PRIVATE Threads::Threads)

find_package(OpenSSL REQUIRED)
add_executable(security_server main.cpp, Logger.cpp Session.cpp Server.cpp)

target_link_libraries(security_server PRIVATE 
    Threads::Threads 
    OpenSSL::SSL 
    OpenSSL::Crypto
)