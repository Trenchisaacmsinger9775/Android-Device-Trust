#include "Protocol.hpp"
#include "AttestationKeys.hpp"

#include <cstring>

Protocol::Builder Protocol::Create()
{
    return Builder();
}

void Protocol::AppendVarint(std::vector<uint8_t>& out, uint64_t value)
{
    while (value >= 0x80)
    {
        out.push_back(static_cast<uint8_t>(value | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

void Protocol::AppendUInt64(std::vector<uint8_t>& out, uint64_t value)
{
    for (int index = 0; index < 8; ++index)
    {
        out.push_back(static_cast<uint8_t>((value >> (index * 8)) & 0xFF));
    }
}

void Protocol::AppendInt64(std::vector<uint8_t>& out, int64_t value)
{
    AppendUInt64(out, static_cast<uint64_t>(value));
}

void Protocol::AppendDouble(std::vector<uint8_t>& out, double value)
{
    uint64_t bits = 0;
    static_assert(sizeof(bits) == sizeof(value), "double size mismatch");
    std::memcpy(&bits, &value, sizeof(bits));
    AppendUInt64(out, bits);
}

void Protocol::Builder::AddBytes(uint64_t fieldId, const std::vector<uint8_t>& value, uint8_t flags)
{
    AddRecord(fieldId, TYPE_BYTES, flags, value);
}

void Protocol::Builder::AddString(uint64_t fieldId, const std::string& value, uint8_t flags)
{
    AddRecord(fieldId, TYPE_STRING, flags, std::vector<uint8_t>(value.begin(), value.end()));
}

void Protocol::Builder::AddUInt64(uint64_t fieldId, uint64_t value)
{
    std::vector<uint8_t> payload;
    AppendUInt64(payload, value);
    AddRecord(fieldId, TYPE_UINT64, FLAG_NONE, payload);
}

void Protocol::Builder::AddInt64(uint64_t fieldId, int64_t value)
{
    std::vector<uint8_t> payload;
    AppendInt64(payload, value);
    AddRecord(fieldId, TYPE_INT64, FLAG_NONE, payload);
}

void Protocol::Builder::AddDouble(uint64_t fieldId, double value)
{
    std::vector<uint8_t> payload;
    AppendDouble(payload, value);
    AddRecord(fieldId, TYPE_DOUBLE, FLAG_NONE, payload);
}

void Protocol::Builder::AddNested(uint64_t fieldId, const Builder& value)
{
    AddRecord(fieldId, TYPE_NESTED, FLAG_NONE, value.Build());
}

void Protocol::Builder::AddHashedBytes(uint64_t fieldId, const std::vector<uint8_t>& value, bool present)
{
    std::vector<uint8_t> payload;
    payload.push_back(present ? 1 : 0);
    AppendUInt64(payload, static_cast<uint64_t>(value.size()));
    AppendUInt64(payload, present ? AttestationKeys::Hash64(value) : 0);
    AddRecord(fieldId, TYPE_HASHED_BYTES, present ? FLAG_NONE : FLAG_ABSENT, payload);
}

std::vector<uint8_t> Protocol::Builder::Build() const
{
    return records;
}

void Protocol::Builder::AddRecord(uint64_t fieldId, uint8_t type, uint8_t flags, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> key = AttestationKeys::DeriveFieldKey(fieldId);
    AppendVarint(records, key.size());
    records.insert(records.end(), key.begin(), key.end());
    records.push_back(type);
    records.push_back(flags);
    AppendVarint(records, payload.size());
    records.insert(records.end(), payload.begin(), payload.end());
}
