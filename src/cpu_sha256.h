#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array> // For std::array

// Define a structure or typedef for the 32-byte SHA256 hash
// Using std::array for better C++ integration
using Sha256Hash = std::array<uint8_t, 32>;

// Function to compute SHA256 hash
// data: pointer to the input data
// len: length of the input data in bytes
// Returns a Sha256Hash object
Sha256Hash cpu_sha256(const uint8_t* data, size_t len);

// Overload for convenience to hash a vector of bytes
Sha256Hash cpu_sha256(const std::vector<uint8_t>& data);

// Overload for convenience to hash a string (will hash its byte representation)
Sha256Hash cpu_sha256(const std::string& data);
