#include <iostream>
#include <asio.hpp>
#include "Logger.hpp"
#include "Session.hpp"

int main() {
    try {
        asio::io_context io_context;
        SecurityLogger logger;
        
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 12345));
        std::cout << "Server started on port 12345..." << std::endl;

        std::function<void()> do_accept = [&]() {
            acceptor.async_accept([&](asio::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(std::move(socket), logger)->start();
                }
                do_accept();
            });
        };

        do_accept();
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return 0;
}