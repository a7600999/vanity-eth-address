#pragma once
#include "cpu_sha256.h"
#include "gpu_sha256.h" // Include the GPU version

// Future: Could add host functions here to manage GPU execution if needed,
// e.g., a function that allocates GPU memory, copies data, launches a kernel
// (if compute_sha256_on_gpu was a __global__ kernel itself), copies results back, etc.
// For now, compute_sha256_on_gpu is a __device__ function, intended to be called
// by another __global__ kernel.
