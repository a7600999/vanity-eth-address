#include "cpu_sha256.h"
#include <vector>
#include <string>
#include <cstring> // For std::memcpy, std::memset
#include <algorithm> // For std::reverse

// Helper function to convert uint32_t to big-endian byte array
inline void uint32_to_be_bytes(uint32_t val, uint8_t* bytes) {
    bytes[0] = (val >> 24) & 0xFF;
    bytes[1] = (val >> 16) & 0xFF;
    bytes[2] = (val >> 8) & 0xFF;
    bytes[3] = val & 0xFF;
}

// Helper function to convert byte array (big-endian) to uint32_t
inline uint32_t be_bytes_to_uint32(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) << 24 |
           static_cast<uint32_t>(bytes[1]) << 16 |
           static_cast<uint32_t>(bytes[2]) << 8  |
           static_cast<uint32_t>(bytes[3]);
}

// SHA-256 constants (K)
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values (H)
static uint32_t h0 = 0x6a09e667;
static uint32_t h1 = 0xbb67ae85;
static uint32_t h2 = 0x3c6ef372;
static uint32_t h3 = 0xa54ff53a;
static uint32_t h4 = 0x510e527f;
static uint32_t h5 = 0x9b05688c;
static uint32_t h6 = 0x1f83d9ab;
static uint32_t h7 = 0x5be0cd19;

// SHA-256 Functions
inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t shr(uint32_t x, uint32_t n) {
    return x >> n;
}

inline uint32_t Sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t Sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}

inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}

inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

Sha256Hash cpu_sha256(const uint8_t* data, size_t len) {
    uint32_t H[8] = {h0, h1, h2, h3, h4, h5, h6, h7};

    // Preprocessing
    std::vector<uint8_t> msg;
    msg.reserve(len + 64); // Reserve space to avoid multiple reallocations

    for (size_t i = 0; i < len; ++i) {
        msg.push_back(data[i]);
    }

    // Append bit '1'
    msg.push_back(0x80);

    // Append '0' bits until message length in bits is congruent to 448 (mod 512)
    // (msg length in bytes * 8) % 512 == 448
    // (msg length in bytes) % 64 == 56
    size_t current_len_bytes = msg.size();
    size_t padding_zeros = (current_len_bytes % 64 <= 56) ? (56 - (current_len_bytes % 64)) : (64 - (current_len_bytes % 64) + 56);
    for (size_t i = 0; i < padding_zeros; ++i) {
        msg.push_back(0x00);
    }

    // Append original length in bits as 64-bit big-endian integer
    uint64_t original_len_bits = len * 8;
    for (int i = 7; i >= 0; --i) {
        msg.push_back((original_len_bits >> (i * 8)) & 0xFF);
    }

    // Process the message in successive 512-bit (64-byte) chunks
    for (size_t chunk_offset = 0; chunk_offset < msg.size(); chunk_offset += 64) {
        uint32_t w[64];
        const uint8_t* chunk = msg.data() + chunk_offset;

        // Prepare message schedule (W)
        for (int i = 0; i < 16; ++i) {
            w[i] = be_bytes_to_uint32(chunk + i * 4);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
        }

        // Initialize working variables
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        // Main loop
        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + k[i] + w[i];
            uint32_t T2 = Sigma0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Add to intermediate hash values
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    Sha256Hash final_hash;
    for (int i = 0; i < 8; ++i) {
        uint32_to_be_bytes(H[i], &final_hash[i * 4]);
    }

    return final_hash;
}

Sha256Hash cpu_sha256(const std::vector<uint8_t>& data) {
    return cpu_sha256(data.data(), data.size());
}

Sha256Hash cpu_sha256(const std::string& data) {
    return cpu_sha256(reinterpret_cast<const uint8_t*>(data.c_str()), data.length());
}
