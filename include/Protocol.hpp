#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint>
#include <cstddef>

inline constexpr uint32_t SECURITY_MAGIC = 0xABCD1234;
inline constexpr size_t DEVICE_NAME_MAX = 32;

#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic_number;  
    uint32_t payload_len;   
    char device_name[DEVICE_NAME_MAX]; 
};
#pragma pack(pop)

#endif // PROTOCOL_HPP