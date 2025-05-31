#include "gpu_base58.h"
#include <cstdint>
#include <cuda_runtime.h>

// Base58 alphabet definition for GPU
static const __device__ char GPU_BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const __device__ uint8_t BASE58_RADIX_GPU = 58;

__device__ int gpu_base58_encode_to_char_array(
    const uint8_t* input_data,
    size_t input_len,
    char* output_buffer,
    size_t output_buffer_size) {

    if (input_data == nullptr || input_len == 0 || output_buffer == nullptr || output_buffer_size == 0) {
        return 0; // Or some error code if we had a system for it
    }

    // Max input length for TRON addresses (prefix + 20 bytes hash + 4 bytes checksum = 25 bytes)
    // Max Base58 length for 25 bytes is ceil(25 * log2(256) / log2(58)) approx 35 chars.
    // We need a temporary buffer for bignum arithmetic.
    // Let's assume input_len won't exceed a practical limit for on-stack arrays, e.g., 64 bytes.
    // If input_len is larger, this approach with fixed-size stack arrays might be problematic.
    if (input_len > 64) { // Safety break for this example implementation
        return -1; // Indicate error: input too large for this device function's buffer
    }
    uint8_t bignum[64]; // Temporary buffer for base conversion, max input_len

    // Copy input data to bignum for manipulation
    for (size_t i = 0; i < input_len; ++i) {
        bignum[i] = input_data[i];
    }

    // 1. Count and handle leading zeros
    size_t leading_zeros = 0;
    for (size_t i = 0; i < input_len && bignum[i] == 0; ++i) {
        leading_zeros++;
    }

    // Temporary buffer to store base58 digits in reverse order
    // Max length: 35 chars for 25 bytes. Add some padding.
    char temp_base58_chars[40]; // Should be enough for up to 25-30 byte inputs
    int temp_chars_count = 0;

    size_t current_bignum_len = input_len;
    size_t first_digit_idx = leading_zeros; // Start processing after leading zeros

    while (first_digit_idx < current_bignum_len) { // While number is > 0
        uint32_t remainder = 0;
        size_t new_len = 0; // Length of the quotient for next iteration
        uint8_t quotient[64]; // Buffer for quotient

        for (size_t i = first_digit_idx; i < current_bignum_len; ++i) {
            uint32_t temp = remainder * 256 + bignum[i];
            uint8_t current_quotient_digit = temp / BASE58_RADIX_GPU;
            remainder = temp % BASE58_RADIX_GPU;

            if (new_len > 0 || current_quotient_digit != 0) { // Avoid leading zeros in quotient
                 if (new_len < 64) quotient[new_len++] = current_quotient_digit;
                 // else { error, quotient buffer too small - should not happen if bignum is sized for input_len}
            }
        }

        if (temp_chars_count < 40) {
            temp_base58_chars[temp_chars_count++] = GPU_BASE58_ALPHABET[remainder];
        } else {
            return -2; // Error: temp_base58_chars buffer too small
        }

        // Update bignum with the quotient for the next iteration
        current_bignum_len = new_len;
        first_digit_idx = 0; // Next iteration processes the full quotient
        for(size_t i=0; i < new_len; ++i) {
            bignum[i] = quotient[i];
        }
        if (new_len == 0) break; // Number is zero
    }

    // Total characters to write
    int final_len = leading_zeros + temp_chars_count;
    if (static_cast<size_t>(final_len) >= output_buffer_size && !(static_cast<size_t>(final_len) == 0 && output_buffer_size ==0) ) { // Check if it fits (allow null term if final_len == output_buffer_size-1)
         // If we need space for null terminator, it should be final_len < output_buffer_size
        return -3; // Error: output_buffer too small
    }

    int output_idx = 0;
    // Add leading '1's
    for (size_t i = 0; i < leading_zeros; ++i) {
        output_buffer[output_idx++] = GPU_BASE58_ALPHABET[0];
    }

    // Add the calculated base58 digits (which are in reverse order in temp_base58_chars)
    for (int i = temp_chars_count - 1; i >= 0; --i) {
        output_buffer[output_idx++] = temp_base58_chars[i];
    }

    // Optional: Null-terminate if space allows and C-style string is expected.
    // The problem asks for length, so null termination is secondary here.
    // if (static_cast<size_t>(output_idx) < output_buffer_size) {
    //    output_buffer[output_idx] = '\0';
    // }

    return output_idx; // Return the number of characters written
}
