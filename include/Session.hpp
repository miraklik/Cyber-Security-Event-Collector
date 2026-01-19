#ifndef SESSION_HPP
#define SESSION_HPP

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <vector>
#include "Logger.hpp"
#include "Protocol.hpp"

using asio::ip::tcp;

class SecurityLogger;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(asio::ssl::stream<tcp::socket> socket, SecurityLogger& logger);
    void start();

private:
    void reset_timeout();
    void read_header();
    void read_payload();

    SecurityLogger& logger_;
    asio::steady_timer timer_;
    PacketHeader header_;
    asio::ssl::stream<tcp::socket> socket_; 
    std::vector<uint8_t> payload_data_;
};

#endif // SESSION_HPP