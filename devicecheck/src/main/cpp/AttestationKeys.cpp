#include "AttestationKeys.hpp"

static constexpr uint64_t MASTER_A = 0x8F3D3A7E2C9B1051ULL;
static constexpr uint64_t MASTER_B = 0xD64A6D1A9E3779B9ULL;
static constexpr uint64_t FNV_OFFSET = 0xCBF29CE484222325ULL;
static constexpr uint64_t FNV_PRIME = 0x100000001B3ULL;

static uint64_t Mix64(uint64_t value)
{
    value ^= value >> 30;
    value *= 0xBF58476D1CE4E5B9ULL;
    value ^= value >> 27;
    value *= 0x94D049BB133111EBULL;
    value ^= value >> 31;
    return value;
}

uint64_t AttestationKeys::Hash64(const std::vector<uint8_t>& input)
{
    uint64_t hash = FNV_OFFSET;
    for (uint8_t byte : input)
    {
        hash ^= byte;
        hash *= FNV_PRIME;
    }
    return Mix64(hash ^ MASTER_A);
}

uint64_t AttestationKeys::Hash64String(const std::string& input)
{
    return Hash64(std::vector<uint8_t>(input.begin(), input.end()));
}

std::vector<uint8_t> AttestationKeys::DeriveBytes(uint64_t domain, const std::vector<uint8_t>& input, size_t length)
{
    std::vector<uint8_t> seed;
    seed.reserve(sizeof(domain) + 1 + input.size());
    for (int index = 0; index < 8; ++index)
    {
        seed.push_back(static_cast<uint8_t>((domain >> (index * 8)) & 0xFF));
    }
    seed.push_back(static_cast<uint8_t>(SCHEMA_VERSION));
    seed.insert(seed.end(), input.begin(), input.end());

    uint64_t stateA = Hash64(seed) ^ MASTER_A;
    uint64_t stateB = Mix64(stateA ^ MASTER_B ^ input.size());
    std::vector<uint8_t> out;
    out.reserve(length);

    while (out.size() < length)
    {
        stateA = Mix64(stateA + 0x9E3779B97F4A7C15ULL + stateB);
        stateB = Mix64(stateB ^ stateA ^ 0xD1B54A32D192ED03ULL);
        uint64_t word = stateA ^ stateB;
        for (int index = 0; index < 8 && out.size() < length; ++index)
        {
            out.push_back(static_cast<uint8_t>((word >> (index * 8)) & 0xFF));
        }
    }

    return out;
}

std::vector<uint8_t> AttestationKeys::DeriveFieldKey(uint64_t fieldId)
{
    std::vector<uint8_t> input;
    for (int index = 0; index < 8; ++index)
    {
        input.push_back(static_cast<uint8_t>((fieldId >> (index * 8)) & 0xFF));
    }
    return DeriveBytes(DOMAIN_FIELD_KEY, input, 16);
}
