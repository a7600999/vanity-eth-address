#pragma once

#include <cstdint>
#include <cuda_runtime.h> // For __device__

// Base58 alphabet (same as CPU version)
// Consider placing this in a shared header or defining it in .cu as __constant__
// extern const char* GPU_BASE58_ALPHABET;

/**
 * @brief Encodes input data (bytes) into a Base58 string (character array) using GPU device code.
 *
 * @param input_data Pointer to the input byte array on the GPU.
 * @param input_len Length of the input byte array.
 * @param output_buffer Pointer to a character array on the GPU where the Base58 string will be stored.
 * @param output_buffer_size The maximum size of the output_buffer.
 * @return The actual length of the encoded Base58 string. If encoding fails or buffer is too small,
 *         it might return 0 or a negative error code (though error handling in device code is limited).
 *         For simplicity, assume buffer is large enough and return length.
 */
__device__ int gpu_base58_encode_to_char_array(
    const uint8_t* input_data,
    size_t input_len,
    char* output_buffer,
    size_t output_buffer_size
);
