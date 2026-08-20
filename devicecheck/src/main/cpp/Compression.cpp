#include "Compression.hpp"

#include <zlib.h>

bool Compression::ZlibCompress(const std::vector<uint8_t>& input, std::vector<uint8_t>& output)
{
    output.clear();
    if (input.empty()) return true;

    uLongf bound = compressBound(static_cast<uLong>(input.size()));
    output.resize(static_cast<size_t>(bound));
    int result = compress2(output.data(), &bound, input.data(), static_cast<uLong>(input.size()), Z_BEST_SPEED);
    if (result != Z_OK)
    {
        output.clear();
        return false;
    }

    output.resize(static_cast<size_t>(bound));
    return true;
}
