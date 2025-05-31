#pragma once

#include <vector>
#include <string>
#include "structures.h" // For Address type
#include <cuda_runtime.h>

// Define a maximum length for TRON address strings on GPU
#define MAX_TRON_ADDR_LENGTH_GPU 50 // Characters

/**
 * @brief Converts a batch of Address structures (20-byte hashes) to TRON Base58Check encoded strings using GPU.
 *
 * @param batch_addresses Vector of Address structures from CPU.
 * @return Vector of TRON Base58Check encoded strings. Returns empty vector on error.
 */
std::vector<std::string> batch_addresses_to_tron_gpu(const std::vector<Address>& batch_addresses);

// CUDA kernel (declaration might not be strictly needed in .h if only called from .cu,
// but good for clarity or if other .cu files were to call it).
// For simplicity, we'll ensure it's defined before use in gpu_tron_utils.cu.
// __global__ void batch_tron_base58check_kernel(
// const uint8_t* d_input_hashes_batch,
// char* d_output_strings_batch,
// int num_addresses
// );
// Actual kernel signature will be in the .cu file.
// The .h only needs the host-callable function for this structure.
