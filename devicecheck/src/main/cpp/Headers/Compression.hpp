#pragma once

#include <cstdint>
#include <vector>

namespace Compression
{
    bool ZlibCompress(const std::vector<uint8_t>& input, std::vector<uint8_t>& output);
}
