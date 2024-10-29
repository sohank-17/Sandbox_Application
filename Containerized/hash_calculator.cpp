#include <openssl/sha.h>
#include <openssl/md5.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>

std::string calculate_md5(const std::string& file_path) {
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5_ctx;
    MD5_Init(&md5_ctx);

    std::ifstream file(file_path, std::ifstream::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file " << file_path << std::endl;
        return "";
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        MD5_Update(&md5_ctx, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        MD5_Update(&md5_ctx, buffer, file.gcount());
    }

    MD5_Final(md5_hash, &md5_ctx);

    std::ostringstream result;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)md5_hash[i];
    }

    return result.str();
}

std::string calculate_sha256(const std::string& file_path) {
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);

    std::ifstream file(file_path, std::ifstream::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file " << file_path << std::endl;
        return "";
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256_ctx, buffer, file.gcount());
    }
    if (file.gcount() > 0) {
        SHA256_Update(&sha256_ctx, buffer, file.gcount());
    }

    SHA256_Final(sha256_hash, &sha256_ctx);

    std::ostringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)sha256_hash[i];
    }

    return result.str();
}

int main() {
    // Input: Absolute file path
    std::string file_path;
    std::cout << "Enter the absolute file path of the binary: ";
    std::cin >> file_path;

    // Calculate MD5 and SHA256 hashes
    std::string md5_hash = calculate_md5(file_path);
    std::string sha256_hash = calculate_sha256(file_path);

    if (!md5_hash.empty() && !sha256_hash.empty()) {
        std::cout << "MD5: " << md5_hash << std::endl;
        std::cout << "SHA256: " << sha256_hash << std::endl;
    } else {
        std::cerr << "Failed to calculate hashes." << std::endl;
    }

    return 0;
}

