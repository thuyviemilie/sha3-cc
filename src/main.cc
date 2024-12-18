#include "sha3.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring> // for strcmp

// Prints the SHA3-256 hash of the given file in hex.
int main(int argc, char *argv[]) {
    bool show_time = false;
    std::string filename;

    if (argc == 3 && std::strcmp(argv[1], "-t") == 0) {
        show_time = true;
        filename = argv[2];
    } else if (argc == 2) {
        filename = argv[1];
    } else {
        std::cerr << "Usage: " << argv[0] << " [-t] <file>\n";
        return 1;
    }

    uint8_t digest[SHA3_256_DIGEST_SIZE];
    std::chrono::steady_clock::time_point start, end;
    if (show_time) {
        start = std::chrono::steady_clock::now();
    }

    if (!sha3_256_file(filename, digest)) {
        std::cerr << "Error reading file: " << argv[1] << "\n";
        return 1;
    }

    if (show_time) {
        end = std::chrono::steady_clock::now();
    }

    for (size_t i = 0; i < SHA3_256_DIGEST_SIZE; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (unsigned)digest[i];
    }
    std::cout << "\n";

    if (show_time) {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        std::cout << "Computational time: " << duration << " ms\n";
    }

    return 0;
}
