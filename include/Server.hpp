#ifndef SERVER_HPP
#define SERVER_HPP

#include <asio.hpp>
#include "Logger.hpp"
#include "Session.hpp"
using asio::ip::tcp;

class SecurityServer {
public:
    SecurityServer(asio::io_context& io_context, short port, SecurityLogger& logger);

private:
    void do_accept();

    tcp::acceptor acceptor_;
    SecurityLogger& logger_;
};

#endif // SERVER_HPP