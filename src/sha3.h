#ifndef SHA3_H
#define SHA3_H

#include <cstddef>
#include <cstdint>
#include <string>

extern const size_t SHA3_256_RATE;
extern const size_t SHA3_256_DIGEST_SIZE;
extern const size_t SHA3_256_NUM_ROUNDS;
extern const size_t BUFFER_SIZE;

static const size_t SHA3_256_STATE_SIZE = 1600 / 8;  // 200 bytes

class SHA3_256 {
public:
    SHA3_256();
    void reset();
    void update(const uint8_t *data, size_t len);
    void finalize(uint8_t *digest);
private:
    uint8_t state_bytes[SHA3_256_STATE_SIZE]; 
    size_t rate_pos;
    bool finalized;

    void absorb_block();
};

bool sha3_256_file(const std::string &filename, uint8_t *out_digest);

// Utility functions for endianness conversion
void store64_le(uint8_t *x, uint64_t u);
uint64_t load64_le(const uint8_t *x);

#endif // SHA3_H