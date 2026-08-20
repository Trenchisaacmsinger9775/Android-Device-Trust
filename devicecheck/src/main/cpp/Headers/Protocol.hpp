#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Protocol
{
    enum ValueType : uint8_t
    {
        TYPE_BYTES = 1,
        TYPE_STRING = 2,
        TYPE_UINT64 = 3,
        TYPE_INT64 = 4,
        TYPE_DOUBLE = 5,
        TYPE_NESTED = 6,
        TYPE_HASHED_BYTES = 7
    };

    enum RecordFlags : uint8_t
    {
        FLAG_NONE = 0,
        FLAG_ZLIB = 1,
        FLAG_ABSENT = 2
    };

    class Builder
    {
    public:
        void AddBytes(uint64_t fieldId, const std::vector<uint8_t>& value, uint8_t flags = FLAG_NONE);
        void AddString(uint64_t fieldId, const std::string& value, uint8_t flags = FLAG_NONE);
        void AddUInt64(uint64_t fieldId, uint64_t value);
        void AddInt64(uint64_t fieldId, int64_t value);
        void AddDouble(uint64_t fieldId, double value);
        void AddNested(uint64_t fieldId, const Builder& value);
        void AddHashedBytes(uint64_t fieldId, const std::vector<uint8_t>& value, bool present);
        std::vector<uint8_t> Build() const;

    private:
        std::vector<uint8_t> records;
        void AddRecord(uint64_t fieldId, uint8_t type, uint8_t flags, const std::vector<uint8_t>& payload);
    };

    Builder Create();
    void AppendVarint(std::vector<uint8_t>& out, uint64_t value);
    void AppendUInt64(std::vector<uint8_t>& out, uint64_t value);
    void AppendInt64(std::vector<uint8_t>& out, int64_t value);
    void AppendDouble(std::vector<uint8_t>& out, double value);
}
