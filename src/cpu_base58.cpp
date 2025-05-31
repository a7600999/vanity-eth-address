#include "cpu_base58.h"
#include <vector>
#include <string>
#include <algorithm> // For std::reverse
#include <stdexcept> // For std::runtime_error if needed for decode later

// Standard TRON/Bitcoin Base58 alphabet
const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const uint8_t BASE58_RADIX = 58;

// Function to encode a raw byte pointer and length into a Base58 string.
std::string cpu_base58_encode(const uint8_t* data_ptr, size_t len) {
    if (len == 0) {
        return "";
    }

    // 1. Convert byte array to a big-endian base256 number
    std::vector<uint8_t> digits(data_ptr, data_ptr + len);

    // 2. Count leading zeros
    size_t leading_zeros = 0;
    for (size_t i = 0; i < len && digits[i] == 0; ++i) {
        leading_zeros++;
    }

    // 3. Base conversion from base256 to base58
    std::string result = "";
    result.reserve(len * 138 / 100 + 1); // Heuristic for result size

    std::vector<uint8_t> temp_digits = digits; // Work on a copy

    while (true) {
        uint32_t remainder = 0;
        std::vector<uint8_t> quotient_digits;
        quotient_digits.reserve(temp_digits.size());

        for (uint8_t digit : temp_digits) {
            uint32_t temp = (static_cast<uint32_t>(remainder) << 8) + digit;
            quotient_digits.push_back(static_cast<uint8_t>(temp / BASE58_RADIX));
            remainder = temp % BASE58_RADIX;
        }

        result += BASE58_ALPHABET[remainder];

        // Remove leading zeros from quotient_digits to check if it's zero
        size_t first_digit_pos = 0;
        while (first_digit_pos < quotient_digits.size() && quotient_digits[first_digit_pos] == 0) {
            first_digit_pos++;
        }

        if (first_digit_pos == quotient_digits.size()) { // All digits were zero
            break;
        }
        // Prepare for next iteration
        temp_digits.assign(quotient_digits.begin() + first_digit_pos, quotient_digits.end());
    }

    // 4. Add '1's for leading zeros (from original data)
    for (size_t i = 0; i < leading_zeros; ++i) {
        result += BASE58_ALPHABET[0];
    }

    // 5. Reverse the result (since remainders were collected in reverse order)
    std::reverse(result.begin(), result.end());

    return result;
}

// Function to encode a byte array (std::vector) into a Base58 string.
std::string cpu_base58_encode(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }
    return cpu_base58_encode(data.data(), data.size());
}

/*
// --- Optional Decode Function (stub for now, can be implemented later) ---
std::vector<uint8_t> cpu_base58_decode(const std::string& base58_str) {
    // Implementation of Base58 decoding would go here.
    // It involves:
    // 1. Mapping Base58 characters back to their integer values.
    // 2. Treating the Base58 string as a big-endian base58 number.
    // 3. Converting this base58 number to a base256 number (byte array).
    // 4. Handling leading '1's which become zero bytes.
    throw std::runtime_error("cpu_base58_decode is not yet implemented.");
    return {};
}
*/
