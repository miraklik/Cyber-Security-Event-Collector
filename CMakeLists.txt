cmake_minimum_required(VERSION 3.20)
project(CyberSecServer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(/opt/homebrew/include)
link_directories(/opt/homebrew/lib)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

add_executable(security_server 
    src/main.cpp 
    src/Logger.cpp 
    src/Session.cpp 
    src/Server.cpp
    src/Database.cpp  
)

target_link_libraries(security_server PRIVATE 
    Threads::Threads 
    OpenSSL::SSL 
    OpenSSL::Crypto
    SQLite3::SQLite3
    sqlite3      
    SQLiteCpp    
)

add_executable(security_agent 
    src/agent_main.cpp
)

target_link_libraries(security_agent PRIVATE 
    Threads::Threads
    OpenSSL::SSL 
    OpenSSL::Crypto
)