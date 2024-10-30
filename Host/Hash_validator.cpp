#include <iostream>
#include <fstream>
#include <string>
#include <sqlite3.h>

std::string db_path = "/opt/sba/malware_hashes.db";

// Function to compare MD5 and SHA256 hashes in the database
bool compare_hashes_in_db(const std::string& md5, const std::string& sha256) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    bool found = false;

    // Open the database
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    // Prepare the SQL query
    std::string query = "SELECT EXISTS (SELECT 1 FROM malware_hashes WHERE md5_hash=? OR sha256_hash=?)";

    if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, 0) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }

    // Bind MD5 and SHA256 hashes
    sqlite3_bind_text(stmt, 1, md5.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sha256.c_str(), -1, SQLITE_STATIC);

    // Execute the query
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int result = sqlite3_column_int(stmt, 0);
        found = result == 1;
    }

    // Cleanup
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return found;
}

int main() {
    std::string md5_hash, sha256_hash;

    // Example: Read MD5 and SHA256 hashes (these values should come from the container)
    std::cout << "Enter MD5 hash: ";
    std::cin >> md5_hash;

    std::cout << "Enter SHA256 hash: ";
    std::cin >> sha256_hash;

    // Compare hashes in the SQLite3 database
    if (compare_hashes_in_db(md5_hash, sha256_hash)) {
        std::cout << "Binary is identified as malware." << std::endl;
    } else {
        std::cout << "Binary is clean (no matching malware found)." << std::endl;
    }

    return 0;
}

