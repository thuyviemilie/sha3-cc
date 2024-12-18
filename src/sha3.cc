#include <iostream>
#include <fstream>
#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <stdexcept>



// Keccak-f[1600] round constants (table 1 in the spec)
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

// Rotation offsets (table 2 in the psec)
static const int KECCAKF_ROTATION_OFFSETS[5][5] = {
    {  0, 36,  3, 41, 18 },
    {  1, 44, 10, 45,  2 },
    { 62,  6, 43, 15, 61 },
    { 28, 55, 25, 21, 56 },
    { 27, 20, 39,  8, 14 }
};



// Keccak-f[1600] permutations
static void keccakf(uint64_t state[25]) {
    for (int round = 0; round < (int)SHA3_256_NUM_ROUNDS; round++) {
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
                uint64_t rotated = (state[x + 5*y] << KECCAKF_ROTATION_OFFSETS[x][y]) |
                                (state[x + 5*y] >> (64 - KECCAKF_ROTATION_OFFSETS[x][y]));
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

SHA3_256::SHA3_256() {
    reset();
}

void SHA3_256::reset() {
    std::memset(state_bytes, 0, sizeof(state_bytes));
    rate_pos = 0;
    finalized = false;
}

void SHA3_256::update(const uint8_t *data, size_t len) {
        if (finalized) {
            throw std::runtime_error("SHA3_256: update() after finalize()");
        }

        // Absorb input
        for (size_t i = 0; i < len; i++) {
            state_bytes[rate_pos++] ^= data[i];
            if (rate_pos == SHA3_256_RATE) {
                absorb_block();
                rate_pos = 0;
            }
        }
}

void SHA3_256::finalize(uint8_t *digest) {
        if (finalized) return;

        // Padding
        state_bytes[rate_pos] ^= 0x06; // domain separation
        state_bytes[SHA3_256_RATE - 1] ^= 0x80; // 1
        absorb_block();

        // Squeeze
        std::memcpy(digest, state_bytes, SHA3_256_DIGEST_SIZE);
        finalized = true;
}

void SHA3_256::absorb_block() {
    uint64_t st[25];
    for (int i = 0; i < 25; i++) {
        st[i] = load64_le(&state_bytes[8*i]);
    }

    keccakf(st);

    for (int i = 0; i < 25; i++) {
        store64_le(&state_bytes[8*i], st[i]);
    }
}