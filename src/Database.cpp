#include "Database.hpp"
#include <iostream>

DatabaseManager::DatabaseManager(const std::string& db_path) 
    : db(db_path, SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE)
{
    db.exec("CREATE TABLE IF NOT EXISTS malware ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "file_hash TEXT UNIQUE, "
            "description TEXT)");
}

bool DatabaseManager::is_malware(const std::string& file_hash) {
    try
    {
        SQLite::Statement query(db, "SELECT COUNT(*) FROM malware WHERE file_hash = ?");
        query.bind(1, file_hash);

        if (query.executeStep()) {
            return query.getColumn(0).getInt() > 0;
        }
    }
    catch (const SQLite::Exception& e) {
        std::cerr << "Database error: " << e.what() << std::endl;
    }

    return false;
}

void DatabaseManager::add_malware(const std::string& file_hash, const std::string& description) {
    try
    {
        SQLite::Statement query(db, "INSERT OR IGNORE INTO malware (file_hash, description) VALUES (?, ?)");
        query.bind(1, file_hash);
        query.bind(2, description);
        query.exec();
    }
    catch (const SQLite::Exception& e) {
        std::cerr << "Database error: " << e.what() << std::endl;
    }
}