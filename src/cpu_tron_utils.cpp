#include "cpu_tron_utils.h"
#include "sha256.h"       // For cpu_sha256
#include "base58.h"       // For cpu_base58_encode
#include <vector>
#include <string>
#include <cstring>        // For memcpy
#include <stdexcept>      // For std::runtime_error (or other error handling)

// TRON_ADDRESS_PREFIX is already declared in cpu_tron_utils.h as const uint8_t

// Function to convert a 20-byte raw hash (vector) to a TRON Base58Check encoded address string.
std::string cpu_to_tron_base58check(const std::vector<uint8_t>& hash20_bytes) {
    if (hash20_bytes.size() != 20) {
        // Consider more robust error handling or logging
        // For now, returning an empty string or a specific error string
        return "Error: Input hash must be 20 bytes long.";
    }

    // 1. Create prefixed_data: TRON_ADDRESS_PREFIX + hash20_bytes
    std::vector<uint8_t> prefixed_data;
    prefixed_data.reserve(1 + 20); // 1 byte for prefix, 20 for hash
    prefixed_data.push_back(TRON_ADDRESS_PREFIX);
    prefixed_data.insert(prefixed_data.end(), hash20_bytes.begin(), hash20_bytes.end());

    // 2. Calculate first SHA256 hash
    Sha256Hash first_hash = cpu_sha256(prefixed_data);

    // 3. Calculate second SHA256 hash (checksum base)
    // cpu_sha256 expects const uint8_t*, Sha256Hash is std::array<uint8_t, 32>
    Sha256Hash second_hash = cpu_sha256(first_hash.data(), first_hash.size());

    // 4. Create data_to_encode: prefixed_data + first 4 bytes of second_hash (checksum)
    std::vector<uint8_t> data_to_encode;
    data_to_encode.reserve(prefixed_data.size() + 4); // 21 bytes + 4 bytes checksum
    data_to_encode.insert(data_to_encode.end(), prefixed_data.begin(), prefixed_data.end());
    data_to_encode.insert(data_to_encode.end(), second_hash.begin(), second_hash.begin() + 4);

    // 5. Encode data_to_encode using cpu_base58_encode
    return cpu_base58_encode(data_to_encode);
}

// Function to convert a 20-byte raw hash (pointer) to a TRON Base58Check encoded address string.
std::string cpu_to_tron_base58check(const uint8_t* hash20_ptr) {
    if (hash20_ptr == nullptr) {
        return "Error: Input hash pointer is null.";
    }
    std::vector<uint8_t> temp_vector(hash20_ptr, hash20_ptr + 20);
    return cpu_to_tron_base58check(temp_vector);
}

// Function to convert a 20-byte address structure to a TRON Base58Check encoded address string.
std::string cpu_to_tron_base58check(const Address& tron_input_address) {
    std::vector<uint8_t> bytes(20);

    // Extract bytes from Address struct in big-endian order
    // Address is {uint32_t a,b,c,d,e;}
    bytes[0] = (tron_input_address.a >> 24) & 0xFF;
    bytes[1] = (tron_input_address.a >> 16) & 0xFF;
    bytes[2] = (tron_input_address.a >> 8) & 0xFF;
    bytes[3] = (tron_input_address.a) & 0xFF;

    bytes[4] = (tron_input_address.b >> 24) & 0xFF;
    bytes[5] = (tron_input_address.b >> 16) & 0xFF;
    bytes[6] = (tron_input_address.b >> 8) & 0xFF;
    bytes[7] = (tron_input_address.b) & 0xFF;

    bytes[8] = (tron_input_address.c >> 24) & 0xFF;
    bytes[9] = (tron_input_address.c >> 16) & 0xFF;
    bytes[10] = (tron_input_address.c >> 8) & 0xFF;
    bytes[11] = (tron_input_address.c) & 0xFF;

    bytes[12] = (tron_input_address.d >> 24) & 0xFF;
    bytes[13] = (tron_input_address.d >> 16) & 0xFF;
    bytes[14] = (tron_input_address.d >> 8) & 0xFF;
    bytes[15] = (tron_input_address.d) & 0xFF;

    bytes[16] = (tron_input_address.e >> 24) & 0xFF;
    bytes[17] = (tron_input_address.e >> 16) & 0xFF;
    bytes[18] = (tron_input_address.e >> 8) & 0xFF;
    bytes[19] = (tron_input_address.e) & 0xFF;

    return cpu_to_tron_base58check(bytes);
}
