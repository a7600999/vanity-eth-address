#pragma once

#include <string>
#include <vector>
#include <cstdint> // For uint8_t

// Standard TRON/Bitcoin Base58 alphabet
extern const char* BASE58_ALPHABET;

// Function to encode a byte array into a Base58 string.
// data: A vector of bytes to encode.
// Returns the Base58 encoded string.
std::string cpu_base58_encode(const std::vector<uint8_t>& data);

// Function to encode a raw byte pointer and length into a Base58 string.
// data_ptr: Pointer to the byte data.
// len: Length of the data.
// Returns the Base58 encoded string.
std::string cpu_base58_encode(const uint8_t* data_ptr, size_t len);

// (Optional for now, but good to keep in mind for a complete library)
// Function to decode a Base58 string back into a byte array.
// std::vector<uint8_t> cpu_base58_decode(const std::string& base58_str);
