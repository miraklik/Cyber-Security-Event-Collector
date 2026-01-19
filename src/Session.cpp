#include "Session.hpp"
#include "Logger.hpp"
#include <asio.hpp>
#include <iostream>

Session::Session(asio::ssl::stream<tcp::socket> socket, SecurityLogger& logger)
    : socket_(std::move(socket)), 
      logger_(logger), 
      timer_(socket_.get_executor()),
      header_{}
{}

void Session::start() {
    read_header();
}

void Session::reset_timeout() {
    auto self(shared_from_this());
    timer_.expires_after(std::chrono::seconds(30));
    timer_.async_wait([this, self](const asio::error_code& ec) {
        if (!ec) { 
            asio::error_code ignored_ec;
            socket_.lowest_layer().shutdown(tcp::socket::shutdown_both, ignored_ec);
            socket_.lowest_layer().close(ignored_ec);
        }
    });
}

void Session::read_header() {
    reset_timeout();
    auto self(shared_from_this());
    asio::async_read(socket_, asio::buffer(&header_, sizeof(PacketHeader)),
        [this, self](asio::error_code ec, std::size_t) {
            if (!ec && header_.magic_number == 0xABCD1234) {
                read_payload();
            }
        });
}

void Session::read_payload() {
    auto self(shared_from_this());
    payload_data_.resize(header_.payload_len);
    asio::async_read(socket_, asio::buffer(payload_data_),
        [this, self](asio::error_code ec, std::size_t) {
            if (!ec) {
                auto ev = std::make_unique<Event>();
                ev->id = static_cast<int>(time(nullptr));
                ev->device = std::string(header_.device_name);
                ev->message = std::string(payload_data_.begin(), payload_data_.end());
                logger_.logEvent(std::move(ev));
                read_header();
            }
        });
}