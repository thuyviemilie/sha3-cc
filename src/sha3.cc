#include <iostream>
#include <fstream>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <stdexcept>

// This implementation follows the Keccak Team's specification for SHA3-256:
// - The capacity is fixed at 512 bits, and the rate at 1088 bits for SHA3-256.
// - The output size is 256 bits.
// - The padding is the standard SHA-3 padding: 0x06, then a 0x80 at the end of the block.

// For more details on Keccak and SHA-3, see:
// https://keccak.team/ and https://en.wikipedia.org/wiki/SHA-3

// Constants for SHA3-256
static const size_t SHA3_256_RATE = 1088 / 8; // 1088 bits = 136 bytes
static const size_t SHA3_256_DIGEST_SIZE = 256 / 8; // 32 bytes

// Keccak-f[1600] constants
static const uint64_t KECCAKF_ROUND_CONSTANTS[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets
static const int KECCAKF_ROTATION_OFFSETS[5][5] = {
    {  0, 36,  3, 41, 18 },
    {  1, 44, 10, 45,  2 },
    { 62,  6, 43, 15, 61 },
    { 28, 55, 25, 21, 56 },
    { 27, 20, 39,  8, 14 }
};

// Convert a 64-bit integer from host endianness to little-endian byte array
static inline void store64_le(uint8_t *x, uint64_t u) {
    for (int i = 0; i < 8; i++) {
        x[i] = (uint8_t)(u & 0xFF);
        u >>= 8;
    }
}

// Convert a 64-bit little-endian byte array to a host 64-bit integer
static inline uint64_t load64_le(const uint8_t *x) {
    uint64_t u = 0;
    for (int i = 0; i < 8; i++) {
        u |= ((uint64_t)x[i]) << (8 * i);
    }
    return u;
}

// Keccak-f[1600] permutation
static void keccakf(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5];
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        uint64_t D[5];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ ((C[(x + 1) % 5]) << 1 | (C[(x + 1) % 5]) >> (64 - 1));
        }

        for (int i = 0; i < 25; i += 5) {
            for (int x = 0; x < 5; x++) {
                state[i + x] ^= D[x];
            }
        }

        // Rho and Pi
        uint64_t B[25];
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                // Rotate A[x,y] by r[x,y]
                uint64_t rotated = (state[x + 5*y] << KECCAKF_ROTATION_OFFSETS[x][y]) |
                                (state[x + 5*y] >> (64 - KECCAKF_ROTATION_OFFSETS[x][y]));
                // Pi step: B[y, (2x+3y)%5] = rotated
                B[y + 5 * ((2*x + 3*y) % 5)] = rotated;
            }
        }

        // Chi
        for (int x = 0; x < 25; x += 5) {
            uint64_t T[5];
            for (int i = 0; i < 5; i++) {
                T[i] = B[x + i];
            }
            for (int i = 0; i < 5; i++) {
                state[x + i] = T[i] ^ ((~T[(i + 1) % 5]) & T[(i + 2) % 5]);
            }
        }

        // Iota
        state[0] ^= KECCAKF_ROUND_CONSTANTS[round];
    }
}

// SHA3-256 class
class SHA3_256 {
public:
    SHA3_256() {
        reset();
    }

    void reset() {
        std::memset(state_bytes, 0, sizeof(state_bytes));
        rate_pos = 0;
        finalized = false;
    }

    void update(const uint8_t *data, size_t len) {
        if (finalized) {
            throw std::runtime_error("SHA3_256: update() after finalize()");
        }

        // Absorb input
        for (size_t i = 0; i < len; i++) {
            state_bytes[rate_pos++] ^= data[i];
            if (rate_pos == SHA3_256_RATE) {
                // Full block
                absorb_block();
                rate_pos = 0;
            }
        }
    }

    void finalize(uint8_t *digest) {
        if (finalized) return;

        // Padding
        state_bytes[rate_pos] ^= 0x06; // domain separation for SHA-3
        state_bytes[SHA3_256_RATE - 1] ^= 0x80;
        absorb_block();

        // Squeeze out the digest
        std::memcpy(digest, state_bytes, SHA3_256_DIGEST_SIZE);

        finalized = true;
    }

private:
    uint8_t state_bytes[200]; // 1600 bits
    size_t rate_pos;
    bool finalized;

    void absorb_block() {
        // Convert state_bytes into 64-bit words
        uint64_t st[25];
        for (int i = 0; i < 25; i++) {
            st[i] = load64_le(&state_bytes[8*i]);
        }

        keccakf(st);

        // Convert back
        for (int i = 0; i < 25; i++) {
            store64_le(&state_bytes[8*i], st[i]);
        }
    }
};

// Helper function to compute SHA3-256 of a file
// Returns true on success, false on failure.
bool sha3_256_file(const std::string &filename, uint8_t *out_digest) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return false;
    }

    SHA3_256 sha3;
    const size_t buf_size = 4096;
    uint8_t buffer[buf_size];

    while (file) {
        file.read(reinterpret_cast<char*>(buffer), buf_size);
        std::streamsize read_count = file.gcount();
        if (read_count > 0) {
            sha3.update(buffer, (size_t)read_count);
        }
    }

    sha3.finalize(out_digest);
    return true;
}

// Example main program
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
