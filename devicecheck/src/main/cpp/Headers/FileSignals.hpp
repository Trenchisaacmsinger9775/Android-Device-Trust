#pragma once

#include "Protocol.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace FileSignals
{
    std::string ReadFile(const char* path, size_t maxBytes);
    bool ReadFileBytes(const char* path, size_t maxBytes, std::vector<uint8_t>& out);
    void AddFileSignals(Protocol::Builder& protocol);
}
