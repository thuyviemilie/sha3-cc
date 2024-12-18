#include "sha3.h"
#include <iostream>
#include <iomanip>

// Usage: ./sha3 <filename>
// Prints the SHA3-256 hash of the given file in hex.
int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file>\n";
        return 1;
    }

    uint8_t digest[SHA3_256_DIGEST_SIZE];
    if (!sha3_256_file(argv[1], digest)) {
        std::cerr << "Error reading file: " << argv[1] << "\n";
        return 1;
    }

    for (size_t i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (unsigned)digest[i];
    }
    std::cout << "\n";

    return 0;
}