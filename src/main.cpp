#include <iostream>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include "Logger.hpp"
#include "Session.hpp"

int main() {
    try {
        asio::io_context io_context;
        SecurityLogger logger;

        asio::ssl::context ssl_ctx(asio::ssl::context::sslv23);
        ssl_ctx.use_certificate_chain_file("cert.pem");
        ssl_ctx.use_private_key_file("key.pem", asio::ssl::context::pem);
        
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 12345));
        std::cout << "Server started on port 12345..." << std::endl;

        std::function<void()> do_accept = [&]() {
            acceptor.async_accept([&](asio::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(asio::ssl::stream<tcp::socket>(std::move(socket), ssl_ctx), logger)->start();
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