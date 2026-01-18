#include <asio.hpp>
#include "Server.hpp"
using asio::ip::tcp;

SecurityServer::SecurityServer(asio::io_context& io_context, short port, SecurityLogger& logger)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
      logger_(logger) {
    do_accept();
}

void SecurityServer::do_accept() {
    acceptor_.async_accept([this](asio::error_code ec, tcp::socket socket) {
        if (!ec) {
            std::make_shared<Session>(std::move(socket), logger_)->start();
        }
        do_accept();
    });
}