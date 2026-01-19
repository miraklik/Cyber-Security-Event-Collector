#ifndef UTILS_HPP
#define UTILS_HPP

#include <string>

inline const std::string PLUS = "[+]";
inline const std::string STAR = "[*]";
inline const std::string SENT = "[SENT]";
inline const std::string ERROR = "[ERROR]";
inline const std::string WARNING = "[WARNING]";

std::string calculate_sha256(const std::string& file_path);

#endif // UTILS_HPP