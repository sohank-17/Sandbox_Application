#!/bin/bash

# Set the directory where the datasets and SQLite3 DB will be stored
DATA_DIR="/opt/sba/"
DB_FILE="$DATA_DIR/malware_hashes.db"

# Create the directory if it doesn't exist
mkdir -p $DATA_DIR

# Initialize the SQLite3 database with a table for the hashes
sqlite3 $DB_FILE <<EOF
CREATE TABLE IF NOT EXISTS malware_hashes (
    id INTEGER PRIMARY KEY,
    hash TEXT,
    hash_type TEXT,
    source TEXT
);
EOF

# Function to download and parse a dataset and add it to the SQLite3 database
download_and_insert() {
    local url=$1
    local hash_type=$2
    local source=$3
    local temp_file="$DATA_DIR/temp_dataset.txt"

    echo "Downloading dataset from $url..."
    curl -s -o $temp_file $url

    # Check if the download was successful
    if [ $? -ne 0 ]; then
        echo "Failed to download dataset from $url"
        return 1
    fi

    echo "Inserting $hash_type hashes from $source into the database..."
    while read -r hash; do
        # Simple validation for MD5 and SHA256 hash lengths
        if [[ ($hash_type == "md5" && ${#hash} == 32) || ($hash_type == "sha256" && ${#hash} == 64) ]]; then
            sqlite3 $DB_FILE "INSERT INTO malware_hashes (hash, hash_type, source) VALUES (?, ?, ?);" "$hash" "$hash_type" "$source"
        else
            echo "Skipping invalid $hash_type hash: $hash"
        fi
    done < $temp_file

    rm $temp_file
}

# Dataset URLs
VIRUSSHARE_URL="https://virusshare.com/download/md5_hashes.txt"
MALWAREBAZAAR_URL="https://bazaar.abuse.ch/downloads/md5_hashes.txt"
MALPEDIA_URL="https://malpedia.caad.fkie.fraunhofer.de/downloads/sha256_hashes.txt"

# Download and insert datasets into SQLite3
download_and_insert $VIRUSSHARE_URL "md5" "VirusShare"
download_and_insert $MALWAREBAZAAR_URL "md5" "MalwareBazaar"
download_and_insert $MALPEDIA_URL "sha256" "Malpedia"

echo "All datasets have been downloaded and stored in $DB_FILE."

