#include "gpu_sha256.h"
#include <cstdint> // For uint_t types
#include <cuda_runtime.h> // For __device__ and other CUDA specifics

// SHA-256 constants (K) - Placed directly in .cu, could be in a shared .cuh if used by multiple .cu files
// For __device__ functions, `static const` makes them local to the compilation unit or inlined.
static const __device__ uint32_t k_sha256[64] = {
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
static const __device__ uint32_t h_init_sha256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// Helper __device__ function to convert uint32_t to big-endian byte array
inline __device__ void uint32_to_be_bytes_gpu(uint32_t val, uint8_t* bytes) {
    bytes[0] = (val >> 24) & 0xFF;
    bytes[1] = (val >> 16) & 0xFF;
    bytes[2] = (val >> 8) & 0xFF;
    bytes[3] = val & 0xFF;
}

// Helper __device__ function to convert byte array (big-endian) to uint32_t
inline __device__ uint32_t be_bytes_to_uint32_gpu(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0]) << 24 |
           static_cast<uint32_t>(bytes[1]) << 16 |
           static_cast<uint32_t>(bytes[2]) << 8  |
           static_cast<uint32_t>(bytes[3]);
}

// SHA-256 Bitwise Operations (marked __device__ or inline __device__)
inline __device__ uint32_t rotr_gpu(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline __device__ uint32_t shr_gpu(uint32_t x, uint32_t n) {
    return x >> n;
}

inline __device__ uint32_t Sigma0_gpu(uint32_t x) {
    return rotr_gpu(x, 2) ^ rotr_gpu(x, 13) ^ rotr_gpu(x, 22);
}

inline __device__ uint32_t Sigma1_gpu(uint32_t x) {
    return rotr_gpu(x, 6) ^ rotr_gpu(x, 11) ^ rotr_gpu(x, 25);
}

inline __device__ uint32_t sigma0_gpu(uint32_t x) {
    return rotr_gpu(x, 7) ^ rotr_gpu(x, 18) ^ shr_gpu(x, 3);
}

inline __device__ uint32_t sigma1_gpu(uint32_t x) {
    return rotr_gpu(x, 17) ^ rotr_gpu(x, 19) ^ shr_gpu(x, 10);
}

inline __device__ uint32_t Ch_gpu(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline __device__ uint32_t Maj_gpu(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ void compute_sha256_on_gpu(const uint8_t* input_data, size_t input_len, uint8_t* output_hash) {
    uint32_t H[8];
    H[0] = h_init_sha256[0];
    H[1] = h_init_sha256[1];
    H[2] = h_init_sha256[2];
    H[3] = h_init_sha256[3];
    H[4] = h_init_sha256[4];
    H[5] = h_init_sha256[5];
    H[6] = h_init_sha256[6];
    H[7] = h_init_sha256[7];

    // Preprocessing: Pad the message
    // This buffer needs to be large enough for the input data + padding.
    // Max padding: 1 byte for 0x80, up to 63 bytes for 0x00, 8 bytes for length. Total ~72 bytes.
    // If input_len is, say, 21 (TRON prefix + address), total padded length is 21 + 1 + (56-21) + 8 = 64 bytes.
    // If input_len is 32 (SHA256 output), total padded length is 32 + 1 + (56-32) + 8 = 64 bytes.
    // If input_len is 60, total padded length is 60 + 1 + (64-60-1+56) + 8 = 128 bytes. (Needs two blocks)
    // Let's use a sufficiently large local buffer, e.g., 128 bytes (two 64-byte blocks).
    // This device function is best for fixed-size small inputs or inputs that result in one or two blocks.
    uint8_t padded_msg_buffer[128]; // Max 2 blocks. For larger inputs, kernel needs to handle chunking.

    size_t current_idx = 0;
    for (size_t i = 0; i < input_len; ++i) {
        padded_msg_buffer[current_idx++] = input_data[i];
    }

    // Append bit '1'
    padded_msg_buffer[current_idx++] = 0x80;

    // Append '0' bits until message length in bits is congruent to 448 (mod 512)
    // (msg length in bytes) % 64 == 56
    size_t num_zeros = (current_idx % 64 <= 56) ? (56 - (current_idx % 64)) : (64 - (current_idx % 64) + 56);
    for (size_t i = 0; i < num_zeros; ++i) {
        padded_msg_buffer[current_idx++] = 0x00;
    }

    // Append original length in bits as 64-bit big-endian integer
    uint64_t original_len_bits = input_len * 8;
    for (int i = 7; i >= 0; --i) {
        padded_msg_buffer[current_idx++] = (original_len_bits >> (i * 8)) & 0xFF;
    }

    size_t total_padded_len = current_idx;

    // Process the message in successive 512-bit (64-byte) chunks
    for (size_t chunk_offset = 0; chunk_offset < total_padded_len; chunk_offset += 64) {
        uint32_t w[64];
        const uint8_t* chunk = padded_msg_buffer + chunk_offset;

        // Prepare message schedule (W)
        for (int i = 0; i < 16; ++i) {
            w[i] = be_bytes_to_uint32_gpu(chunk + i * 4);
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = sigma1_gpu(w[i - 2]) + w[i - 7] + sigma0_gpu(w[i - 15]) + w[i - 16];
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
            uint32_t T1 = h + Sigma1_gpu(e) + Ch_gpu(e, f, g) + k_sha256[i] + w[i];
            uint32_t T2 = Sigma0_gpu(a) + Maj_gpu(a, b, c);
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

    // Write the final hash to output_hash in big-endian
    for (int i = 0; i < 8; ++i) {
        uint32_to_be_bytes_gpu(H[i], output_hash + i * 4);
    }
}
