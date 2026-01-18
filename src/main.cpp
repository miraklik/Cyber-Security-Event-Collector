#include <iostream>
#include <asio.hpp>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <string>
#include <chrono>
using asio::ip::tcp;


struct Event {
    int id;
    std::string device;
    std::string message;
};

#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic_number; 
    uint32_t payload_len;   
    char device_name[32];  
};
#pragma pack(pop)

class SecurityLogger {
public:
    void logEvent(std::unique_ptr<Event> event) {
        std::lock_guard<std::mutex> lock(mtx_);
        std::cout << "[LOG][" << event->id << "] Device: " << event->device 
                  << " | Msg: " << event->message << std::endl;
        events_.push_back(std::move(event));
    }

private:
    std::vector<std::unique_ptr<Event>> events_;
    std::mutex mtx_;
};


class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket, SecurityLogger& logger)
        : socket_(std::move(socket)), 
          logger_(logger), 
          timer_(socket_.get_executor()) {}

    void start() {
        std::cout << "[*] New agent connected: " << socket_.remote_endpoint() << std::endl;
        read_header();
    }

private:
    void reset_timeout() {
        auto self(shared_from_this());
        timer_.expires_after(std::chrono::seconds(30));
        timer_.async_wait([this, self](const asio::error_code& ec) {
            if (!ec) {
                std::cerr << "[-] Session timeout for " << header_.device_name << ". Closing." << std::endl;
                socket_.close();
            }
        });
    }

    void read_header() {
        reset_timeout();
        auto self(shared_from_this());
        
        asio::async_read(socket_, asio::buffer(&header_, sizeof(PacketHeader)),
            [this, self](asio::error_code ec, std::size_t) {
                if (!ec) {
                    if (header_.magic_number == 0xABCD1234) {
                        if (header_.payload_len > 1024 * 1024) {
                            std::cerr << "[!] Payload too large. Dropping client." << std::endl;
                            return;
                        }
                        read_payload();
                    } else {
                        std::cerr << "[!] Invalid magic number. Closing connection." << std::endl;
                    }
                }
            });
    }

    void read_payload() {
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

    tcp::socket socket_;
    SecurityLogger& logger_;
    asio::steady_timer timer_;
    PacketHeader header_;
    std::vector<uint8_t> payload_data_;
};

class SecurityServer {
public:
    SecurityServer(asio::io_context& io_context, short port, SecurityLogger& logger)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)),
          logger_(logger) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept([this](asio::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::make_shared<Session>(std::move(socket), logger_)->start();
            }
            do_accept();
        });
    }

    tcp::acceptor acceptor_;
    SecurityLogger& logger_;
};

int main() {
    try {
        asio::io_context io_context;
        SecurityLogger logger;

        SecurityServer server(io_context, 12345, logger);

        std::cout << "[+] Security Infrastructure Server started on port 12345" << std::endl;
        io_context.run();
    } catch (std::exception& e) {
        std::cerr << "[CRITICAL] " << e.what() << std::endl;
    }
    return 0;
}