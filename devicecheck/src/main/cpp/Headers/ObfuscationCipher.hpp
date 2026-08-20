#pragma once

#include <cstdint>
#include <vector>

namespace ObfuscationCipher
{
    std::vector<uint8_t> Seal(const std::vector<uint8_t>& header, const std::vector<uint8_t>& body, const std::vector<uint8_t>& challenge);
}
