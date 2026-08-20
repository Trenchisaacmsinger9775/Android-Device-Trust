#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace AttestationKeys
{
    static constexpr uint32_t SCHEMA_VERSION = 1;
    static constexpr uint64_t DOMAIN_FIELD_KEY = 0x5F456F88A77105C9ULL;
    static constexpr uint64_t DOMAIN_CHALLENGE_HASH = 0xB05152410320104FULL;
    static constexpr uint64_t DOMAIN_PAYLOAD_CIPHER = 0x8034F7A1C55B651DULL;

    std::vector<uint8_t> DeriveFieldKey(uint64_t fieldId);
    std::vector<uint8_t> DeriveBytes(uint64_t domain, const std::vector<uint8_t>& input, size_t length);
    uint64_t Hash64(const std::vector<uint8_t>& input);
    uint64_t Hash64String(const std::string& input);
}
