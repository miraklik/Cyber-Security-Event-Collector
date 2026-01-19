#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/sha.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>
#include <format>
#include <set>
#include <thread>
#include "Protocol.hpp"
#include "Utils.hpp"

using asio::ip::tcp;
namespace fs = std::filesystem;

std::string calculate_sha256(const std::string& file_path) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) return "";

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount()) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void send_alert(asio::ssl::stream<tcp::socket>& ssl_socket, const fs::path& file_path) {
    std::string filename = file_path.filename().string();
    std::string full_path = file_path.string();

    std::string hash = calculate_sha256(full_path);
    if (hash.empty()) {
        std::cerr << std::format("{} Could not calculate hash for: {}", ERROR, filename) << std::endl;
        return;
    }

    PacketHeader header;
    header.magic_number = SECURITY_MAGIC;
    std::string msg = "New File Detected: " + filename;
    header.payload_len = static_cast<uint32_t>(msg.size());
    
    std::strncpy(header.device_name, "SecOpsDevice", DEVICE_NAME_MAX);
    std::strncpy(header.file_hash, hash.c_str(), HASH_SIZE);

    try {
        asio::write(ssl_socket, asio::buffer(&header, sizeof(header)));
        asio::write(ssl_socket, asio::buffer(msg));
        std::cout << std::format("{} Alert sent! File: {} | Hash: {:.8}...", SENT, filename, hash) << std::endl;
    } catch (std::exception& e) {
        std::cerr << std::format("{} Send failed: {}", ERROR, e.what()) << std::endl;
    }
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

        std::set<std::string> processed_files;

        while (true) {
            for (const auto& entry : fs::directory_iterator(path_to_watch)) {
                std::string fname = entry.path().filename().string();
                
                if (processed_files.find(fname) == processed_files.end()) {
                    send_alert(ssl_stream, entry.path());
                    processed_files.insert(fname); 
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }

    } catch (std::exception& e) {
        std::cerr << std::format("{} Agent Error: {}", ERROR, e.what()) << std::endl;
    }
    return 0;
}