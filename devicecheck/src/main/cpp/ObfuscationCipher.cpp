#include "ObfuscationCipher.hpp"
#include "AttestationKeys.hpp"
#include "Protocol.hpp"

static uint64_t RotateLeft(uint64_t value, int bits)
{
    return (value << bits) | (value >> (64 - bits));
}

static uint64_t NextWord(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d)
{
    a += b;
    d ^= a;
    d = RotateLeft(d, 32);
    c += d;
    b ^= c;
    b = RotateLeft(b, 24);
    a += b;
    d ^= a;
    d = RotateLeft(d, 16);
    c += d;
    b ^= c;
    b = RotateLeft(b, 63);
    return a ^ b ^ c ^ d;
}

std::vector<uint8_t> ObfuscationCipher::Seal(const std::vector<uint8_t>& header, const std::vector<uint8_t>& body, const std::vector<uint8_t>& challenge)
{
    std::vector<uint8_t> seed = header;
    seed.insert(seed.end(), challenge.begin(), challenge.end());
    std::vector<uint8_t> material = AttestationKeys::DeriveBytes(AttestationKeys::DOMAIN_PAYLOAD_CIPHER, seed, 32);

    uint64_t a = 0;
    uint64_t b = 0;
    uint64_t c = 0;
    uint64_t d = 0;
    for (int index = 0; index < 8; ++index)
    {
        a |= static_cast<uint64_t>(material[index]) << (index * 8);
        b |= static_cast<uint64_t>(material[index + 8]) << (index * 8);
        c |= static_cast<uint64_t>(material[index + 16]) << (index * 8);
        d |= static_cast<uint64_t>(material[index + 24]) << (index * 8);
    }

    std::vector<uint8_t> out = header;
    std::vector<uint8_t> cipher = body;
    uint64_t stream = 0;
    for (size_t index = 0; index < cipher.size(); ++index)
    {
        if ((index % 8) == 0)
        {
            stream = NextWord(a, b, c, d);
        }
        cipher[index] ^= static_cast<uint8_t>((stream >> ((index % 8) * 8)) & 0xFF);
    }

    out.insert(out.end(), cipher.begin(), cipher.end());

    std::vector<uint8_t> tagInput = out;
    tagInput.insert(tagInput.end(), challenge.begin(), challenge.end());
    uint64_t tagA = AttestationKeys::Hash64(tagInput);
    tagInput.push_back(0xA5);
    uint64_t tagB = AttestationKeys::Hash64(tagInput);
    Protocol::AppendUInt64(out, tagA);
    Protocol::AppendUInt64(out, tagB);
    return out;
}
