#pragma once

#include <cstdint>
#include <cuda_runtime.h> // For __device__

// Using the same Sha256Hash type from cpu_sha256.h for consistency if it's just std::array
// If not already included by whatever will include this, ensure Sha256Hash is known
// For device code, it's often easier to work with raw pointers or fixed-size C-style arrays.
// The output_hash must point to a 32-byte buffer on the GPU.

/**
 * @brief Computes the SHA256 hash of the input data using GPU device code.
 *
 * @param input_data Pointer to the input data on the GPU.
 * @param input_len Length of the input data in bytes.
 * @param output_hash Pointer to a 32-byte buffer on the GPU where the hash will be stored.
 */
__device__ void compute_sha256_on_gpu(const uint8_t* input_data, size_t input_len, uint8_t* output_hash);
