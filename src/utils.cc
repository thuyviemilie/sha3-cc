#include "sha3.h"
#include <fstream>
#include <iostream>

const size_t SHA3_256_RATE = 136;
const size_t SHA3_256_DIGEST_SIZE = 32;
const size_t SHA3_256_NUM_ROUNDS = 24;
const size_t BUFFER_SIZE = 4096;

void store64_le(uint8_t *x, uint64_t u) {
    for (int i = 0; i < 8; i++) {
        x[i] = (uint8_t)(u & 0xFF);
        u >>= 8;
    }
}

uint64_t load64_le(const uint8_t *x) {
    uint64_t u = 0;
    for (int i = 0; i < 8; i++) {
        u |= ((uint64_t)x[i]) << (8 * i);
    }
    return u;
}

// Helper function to compute SHA3-256 of a file
// Returns true on success, false on failure.
bool sha3_256_file(const std::string &filename, uint8_t *out_digest) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return false;
    }

    SHA3_256 sha3;
    uint8_t buffer[BUFFER_SIZE];

    while (file) {
        file.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
        std::streamsize read_count = file.gcount();
        if (read_count > 0) {
            sha3.update(buffer, (size_t)read_count);
        }
    }

    sha3.finalize(out_digest);
    return true;
}