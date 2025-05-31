#include "gpu_tron_utils.h"
#include "gpu_sha256.h"   // For compute_sha256_on_gpu
#include "gpu_base58.h"   // For gpu_base58_encode_to_char_array
#include "structures.h"   // For Address type

#include <vector>
#include <string>
#include <cuda_runtime.h>
#include <cstring>        // For std::strlen, std::memcpy (on host)
#include <cstdio>         // For printf (debugging on host)

// Device constant for TRON address prefix
static const __device__ uint8_t TRON_ADDRESS_PREFIX_GPU = 0x41;

// Kernel implementation
__global__ void batch_tron_base58check_kernel(
    const uint8_t* d_input_hashes_batch, // Flat array of 20-byte hashes
    char* d_output_strings_batch,        // Flat char array for output strings
    int num_addresses) {

    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx < num_addresses) {
        // Pointer to the start of the current 20-byte hash for this thread
        const uint8_t* current_hash_ptr = &d_input_hashes_batch[idx * 20];

        // Pointer to the start of the output buffer for this thread's address string
        char* current_output_str_ptr = &d_output_strings_batch[idx * MAX_TRON_ADDR_LENGTH_GPU];

        // Intermediate buffers for calculations (on thread's local memory/stack)
        uint8_t prefixed_data[21];         // TRON_PREFIX (1) + hash (20)
        uint8_t first_sha256_hash[32];     // Output of first SHA256
        uint8_t second_sha256_hash[32];    // Output of second SHA256 (checksum base)
        uint8_t data_to_encode[25];        // prefixed_data (21) + checksum (4)

        // Step 1: Prepare prefixed_data = TRON_ADDRESS_PREFIX_GPU + 20-byte hash
        prefixed_data[0] = TRON_ADDRESS_PREFIX_GPU;
        for (int i = 0; i < 20; ++i) {
            prefixed_data[i + 1] = current_hash_ptr[i];
        }

        // Step 2: Calculate first SHA256 hash of prefixed_data
        compute_sha256_on_gpu(prefixed_data, 21, first_sha256_hash);

        // Step 3: Calculate second SHA256 hash of the first hash (this is the checksum base)
        compute_sha256_on_gpu(first_sha256_hash, 32, second_sha256_hash);

        // Step 4: Prepare data_to_encode = prefixed_data + first 4 bytes of second_sha256_hash (checksum)
        for (int i = 0; i < 21; ++i) {
            data_to_encode[i] = prefixed_data[i];
        }
        for (int i = 0; i < 4; ++i) {
            data_to_encode[21 + i] = second_sha256_hash[i];
        }

        // Step 5: Base58 encode data_to_encode into the output buffer for the current thread
        int encoded_len = gpu_base58_encode_to_char_array(
            data_to_encode,
            25, // Length of data_to_encode (1 + 20 + 4)
            current_output_str_ptr,
            MAX_TRON_ADDR_LENGTH_GPU
        );

        // Ensure null termination if the encoder doesn't do it and space allows
        if (encoded_len >= 0 && encoded_len < MAX_TRON_ADDR_LENGTH_GPU) {
            current_output_str_ptr[encoded_len] = '\0';
        } else if (encoded_len < 0) {
            // Handle encoding error, e.g., by writing an error marker or empty string
            // For simplicity, we might just get a truncated or incorrect string.
            // A robust implementation would signal error.
            current_output_str_ptr[0] = '\0'; // Empty string on error
        }
        // If encoded_len == MAX_TRON_ADDR_LENGTH_GPU, it might not be null-terminated.
        // The host side should be careful.
    }
}

// Host wrapper function
std::vector<std::string> batch_addresses_to_tron_gpu(const std::vector<Address>& batch_addresses) {
    std::vector<std::string> result_strings;
    int num_addresses = batch_addresses.size();

    if (num_addresses == 0) {
        return result_strings;
    }

    // Prepare flat input for GPU: std::vector<uint8_t> h_input_hashes_flat
    std::vector<uint8_t> h_input_hashes_flat(num_addresses * 20);
    for (int i = 0; i < num_addresses; ++i) {
        const Address& addr = batch_addresses[i];
        size_t offset = i * 20;
        // Convert Address struct (5 x uint32_t) to 20 bytes, big-endian
        h_input_hashes_flat[offset + 0] = (addr.a >> 24) & 0xFF;
        h_input_hashes_flat[offset + 1] = (addr.a >> 16) & 0xFF;
        h_input_hashes_flat[offset + 2] = (addr.a >> 8) & 0xFF;
        h_input_hashes_flat[offset + 3] = (addr.a) & 0xFF;

        h_input_hashes_flat[offset + 4] = (addr.b >> 24) & 0xFF;
        h_input_hashes_flat[offset + 5] = (addr.b >> 16) & 0xFF;
        h_input_hashes_flat[offset + 6] = (addr.b >> 8) & 0xFF;
        h_input_hashes_flat[offset + 7] = (addr.b) & 0xFF;

        h_input_hashes_flat[offset + 8] = (addr.c >> 24) & 0xFF;
        h_input_hashes_flat[offset + 9] = (addr.c >> 16) & 0xFF;
        h_input_hashes_flat[offset + 10] = (addr.c >> 8) & 0xFF;
        h_input_hashes_flat[offset + 11] = (addr.c) & 0xFF;

        h_input_hashes_flat[offset + 12] = (addr.d >> 24) & 0xFF;
        h_input_hashes_flat[offset + 13] = (addr.d >> 16) & 0xFF;
        h_input_hashes_flat[offset + 14] = (addr.d >> 8) & 0xFF;
        h_input_hashes_flat[offset + 15] = (addr.d) & 0xFF;

        h_input_hashes_flat[offset + 16] = (addr.e >> 24) & 0xFF;
        h_input_hashes_flat[offset + 17] = (addr.e >> 16) & 0xFF;
        h_input_hashes_flat[offset + 18] = (addr.e >> 8) & 0xFF;
        h_input_hashes_flat[offset + 19] = (addr.e) & 0xFF;
    }

    uint8_t* d_input_hashes_batch = nullptr;
    char* d_output_strings_batch = nullptr;
    cudaError_t err;

    // Allocate GPU memory
    size_t input_size_bytes = num_addresses * 20;
    size_t output_size_bytes = num_addresses * MAX_TRON_ADDR_LENGTH_GPU * sizeof(char);

    err = cudaMalloc((void**)&d_input_hashes_batch, input_size_bytes);
    if (err != cudaSuccess) {
        // fprintf(stderr, "cudaMalloc for d_input_hashes_batch failed: %s\n", cudaGetErrorString(err));
        return result_strings; // Return empty
    }
    err = cudaMalloc((void**)&d_output_strings_batch, output_size_bytes);
    if (err != cudaSuccess) {
        // fprintf(stderr, "cudaMalloc for d_output_strings_batch failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_input_hashes_batch);
        return result_strings; // Return empty
    }

    // Copy input data from Host to Device
    err = cudaMemcpy(d_input_hashes_batch, h_input_hashes_flat.data(), input_size_bytes, cudaMemcpyHostToDevice);
    if (err != cudaSuccess) {
        // fprintf(stderr, "cudaMemcpy H2D for input failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_input_hashes_batch);
        cudaFree(d_output_strings_batch);
        return result_strings;
    }

    // Configure and launch kernel
    int threads_per_block = 256;
    int blocks_per_grid = (num_addresses + threads_per_block - 1) / threads_per_block;

    batch_tron_base58check_kernel<<<blocks_per_grid, threads_per_block>>>(
        d_input_hashes_batch,
        d_output_strings_batch,
        num_addresses
    );

    err = cudaGetLastError(); // Check for launch errors
    if (err != cudaSuccess) {
        // fprintf(stderr, "Kernel launch failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_input_hashes_batch);
        cudaFree(d_output_strings_batch);
        return result_strings;
    }

    // Copy results from Device to Host
    std::vector<char> h_output_strings_batch(output_size_bytes);
    err = cudaMemcpy(h_output_strings_batch.data(), d_output_strings_batch, output_size_bytes, cudaMemcpyDeviceToHost);
    if (err != cudaSuccess) {
        // fprintf(stderr, "cudaMemcpy D2H for output failed: %s\n", cudaGetErrorString(err));
        cudaFree(d_input_hashes_batch);
        cudaFree(d_output_strings_batch);
        return result_strings;
    }

    // Synchronize and check for any async errors
    err = cudaDeviceSynchronize();
    if (err != cudaSuccess) {
        // fprintf(stderr, "cudaDeviceSynchronize failed after kernel: %s\n", cudaGetErrorString(err));
        cudaFree(d_input_hashes_batch);
        cudaFree(d_output_strings_batch);
        return result_strings;
    }

    // Convert flat char array to vector of strings
    result_strings.reserve(num_addresses);
    for (int i = 0; i < num_addresses; ++i) {
        char* current_addr_str_ptr = &h_output_strings_batch[i * MAX_TRON_ADDR_LENGTH_GPU];
        // Use strlen to get actual length, assuming null termination by kernel or Base58 encoder
        // Or, if gpu_base58_encode_to_char_array returned lengths, use those (more complex to pass back)
        result_strings.push_back(std::string(current_addr_str_ptr, strnlen(current_addr_str_ptr, MAX_TRON_ADDR_LENGTH_GPU) ));
    }

    // Free GPU memory
    cudaFree(d_input_hashes_batch);
    cudaFree(d_output_strings_batch);

    return result_strings;
}
