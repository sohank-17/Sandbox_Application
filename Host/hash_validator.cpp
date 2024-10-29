#include <iostream>
#include <unordered_set>
#include <fstream>
#include <string>

std::unordered_set<std::string> loadHashDataset(const std::string& filePath) {
    std::unordered_set<std::string> hashSet;
    std::ifstream file(filePath);
    std::string line;
    
    if (file.is_open()) {
        while (getline(file, line)) {
            hashSet.insert(line); // Insert each hash into the set
        }
        file.close();
    } else {
        std::cerr << "Unable to open file: " << filePath << std::endl;
    }
    
    return hashSet;
}

bool isMalicious(const std::string& sha256Hash, const std::string& md5Hash,
                 const std::unordered_set<std::string>& hashDataset1,
                 const std::unordered_set<std::string>& hashDataset2,
                 const std::unordered_set<std::string>& hashDataset3) {
    
    if (hashDataset1.count(sha256Hash) || hashDataset1.count(md5Hash) ||
        hashDataset2.count(sha256Hash) || hashDataset2.count(md5Hash) ||
        hashDataset3.count(sha256Hash) || hashDataset3.count(md5Hash)) {
        return true;
    }
    return false;
}

int main() {
    std::unordered_set<std::string> hashDataset1 = loadHashDataset("dataset1.txt");
    std::unordered_set<std::string> hashDataset2 = loadHashDataset("dataset2.txt");
    std::unordered_set<std::string> hashDataset3 = loadHashDataset("dataset3.txt");

    std::string sha256Hash = "example_sha256_hash";
    std::string md5Hash = "example_md5_hash";

    if (isMalicious(sha256Hash, md5Hash, hashDataset1, hashDataset2, hashDataset3)) {
        std::cout << "The binary is identified as malicious." << std::endl;
    } else {
        std::cout << "The binary is clean." << std::endl;
    }

    return 0;
}

