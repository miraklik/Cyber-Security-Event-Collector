#ifndef DATABASE_HPP
#define DATABASE_HPP

#include <string>
#include <SQLiteCpp/SQLiteCpp.h>

class DatabaseManager {
public:
    DatabaseManager(const std::string& db_path);

    bool is_malware(const std::string& file_hash);
    void add_malware(const std::string& file_hash, const std::string& description);

private:
    SQLite::Database db;
};

#endif // DATABASE_HPP