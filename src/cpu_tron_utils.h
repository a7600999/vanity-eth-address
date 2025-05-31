#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "structures.h" // For Address type (assuming it holds 20 bytes appropriately)
                        // Or use std::array<uint8_t, 20> if Address is not suitable.

// TRON address prefix
const uint8_t TRON_ADDRESS_PREFIX = 0x41;

// Function to convert a 20-byte address structure to a TRON Base58Check encoded address string.
// tron_input_address: The Address structure containing the 20-byte hash.
std::string cpu_to_tron_base58check(const Address& tron_input_address);

// Function to convert a 20-byte raw hash (vector) to a TRON Base58Check encoded address string.
// hash20_bytes: A vector of 20 bytes representing the address hash.
std::string cpu_to_tron_base58check(const std::vector<uint8_t>& hash20_bytes);

// Function to convert a 20-byte raw hash (pointer) to a TRON Base58Check encoded address string.
// hash20_ptr: Pointer to an array of 20 bytes.
std::string cpu_to_tron_base58check(const uint8_t* hash20_ptr);
