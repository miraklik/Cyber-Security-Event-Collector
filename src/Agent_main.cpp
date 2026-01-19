#include <asio.hpp>
#include <asio/ssl.hpp>
#include <iostream>
#include <string>
#include <filesystem>
#include <format>
#include <thread>
#include "Protocol.hpp"
#include "Utils.hpp"

using asio::ip::tcp;
namespace fs = std::filesystem;

void send_alert(asio::ssl::stream<tcp::socket>& ssl_socket, const std::string& filename) {
    PacketHeader header;
    header.magic_number = SECURITY_MAGIC;

    std::string msg = "New File Detected: " + filename;
    header.payload_len = msg.size();
    std::strncpy(header.device_name, "SecOpsDevice", DEVICE_NAME_MAX);

    asio::write(ssl_socket, asio::buffer(&header, sizeof(header)));
    asio::write(ssl_socket, asio::buffer(msg));

    std::cout << std::format("{} Alert for file: {}", SENT, filename) << std::endl;
}

int main() {
    try {
        asio::io_context io_context;
        asio::ssl::context ssl_ctx(asio::ssl::context::sslv23);
        ssl_ctx.set_verify_mode(asio::ssl::verify_none);

        asio::ssl::stream<tcp::socket> ssl_stream(io_context, ssl_ctx);
        tcp::resolver resolver(io_context);
        
        asio::connect(ssl_stream.lowest_layer(), resolver.resolve("127.0.0.1", "12345"));
        ssl_stream.handshake(asio::ssl::stream_base::client);
        
        std::cout << std::format("{} Connected to Security Server over TLS!", PLUS) << std::endl;

        fs::path path_to_watch = "./watch_folder"; 
        if (!fs::exists(path_to_watch)) fs::create_directory(path_to_watch);

        std::cout << std::format("{} Monitoring folder: {}", STAR, path_to_watch) << std::endl;

        while (true) {
            for (const auto& entry : fs::directory_iterator(path_to_watch)) {
                send_alert(ssl_stream, entry.path().filename().string());
            }
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }

    } catch (std::exception& e) {
        std::cerr << std::format("{} Agent Error: {}", ERROR, e.what()) << std::endl;
    }
    return 0;
}