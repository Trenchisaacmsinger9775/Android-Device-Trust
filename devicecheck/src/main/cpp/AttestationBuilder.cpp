#include "AttestationBuilder.hpp"
#include "AttestationKeys.hpp"
#include "FileSignals.hpp"
#include "FingerprintSignals.hpp"
#include "FrameworkSignals.hpp"
#include "IntegritySignals.hpp"
#include "KeystoreAttestation.hpp"
#include "ObfuscationCipher.hpp"
#include "ProcSignals.hpp"
#include "Protocol.hpp"
#include "SignalIds.hpp"
#include "VulkanSignals.hpp"

#include <ctime>
#include <fcntl.h>
#include <unistd.h>

static uint64_t NowMillis()
{
    timespec time{};
    clock_gettime(CLOCK_REALTIME, &time);
    return static_cast<uint64_t>(time.tv_sec) * 1000ULL + static_cast<uint64_t>(time.tv_nsec / 1000000ULL);
}

static uint64_t MonoNanos()
{
    timespec time{};
    clock_gettime(CLOCK_MONOTONIC, &time);
    return static_cast<uint64_t>(time.tv_sec) * 1000000000ULL + static_cast<uint64_t>(time.tv_nsec);
}

static std::vector<uint8_t> RandomBytes(size_t length)
{
    std::vector<uint8_t> out(length);
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
    {
        size_t offset = 0;
        while (offset < out.size())
        {
            ssize_t bytesRead = read(fd, out.data() + offset, out.size() - offset);
            if (bytesRead <= 0)
            {
                break;
            }
            offset += static_cast<size_t>(bytesRead);
        }
        close(fd);
    }
    uint64_t fallback = MonoNanos() ^ NowMillis();
    for (size_t index = 0; index < out.size(); ++index)
    {
        fallback = (fallback * 6364136223846793005ULL) + 1442695040888963407ULL;
        out[index] ^= static_cast<uint8_t>((fallback >> 32) & 0xFF);
    }
    return out;
}

static void AppendHeader(std::vector<uint8_t>& header, uint64_t startWallMs, uint64_t startMonoNs, const std::vector<uint8_t>& challengeHash, const std::vector<uint8_t>& nonce)
{
    header.push_back('D');
    header.push_back('C');
    header.push_back('A');
    header.push_back('1');
    Protocol::AppendVarint(header, 1);
    Protocol::AppendVarint(header, AttestationKeys::SCHEMA_VERSION);
    Protocol::AppendUInt64(header, startWallMs);
    Protocol::AppendUInt64(header, startMonoNs);
    Protocol::AppendVarint(header, challengeHash.size());
    header.insert(header.end(), challengeHash.begin(), challengeHash.end());
    Protocol::AppendVarint(header, nonce.size());
    header.insert(header.end(), nonce.begin(), nonce.end());
}

std::vector<uint8_t> AttestationBuilder::Build(JNIEnv* env, jobject context, const std::vector<uint8_t>& challenge)
{
    uint64_t startWallMs = NowMillis();
    uint64_t startMonoNs = MonoNanos();
    std::vector<uint8_t> nonce = RandomBytes(32);
    std::vector<uint8_t> challengeHash = AttestationKeys::DeriveBytes(AttestationKeys::DOMAIN_CHALLENGE_HASH, challenge, 16);

    Protocol::Builder protocol = Protocol::Create();
    protocol.AddUInt64(SignalIds::META_SCHEMA_VERSION, AttestationKeys::SCHEMA_VERSION);
    protocol.AddUInt64(SignalIds::TIME_WALL_START_MS, startWallMs);
    protocol.AddUInt64(SignalIds::TIME_MONO_START_NS, startMonoNs);
    protocol.AddBytes(SignalIds::FRESH_CHALLENGE_HASH, challengeHash);
    protocol.AddBytes(SignalIds::FRESH_NONCE, nonce);
    protocol.AddBytes(SignalIds::FRESH_RANDOM_0, RandomBytes(32));
    protocol.AddBytes(SignalIds::FRESH_RANDOM_1, RandomBytes(32));

    ProcSignals::AddProcSignals(protocol);
    FileSignals::AddFileSignals(protocol);
    FrameworkSignals::AddFrameworkSignals(env, context, protocol);
    FingerprintSignals::AddFingerprintSignals(env, context, protocol);
    VulkanSignals::AddVulkanSignals(protocol);
    IntegritySignals::AddIntegritySignals(protocol);
    KeystoreAttestation::AddKeystoreAttestation(env, context, challenge, protocol);

    uint64_t endWallMs = NowMillis();
    uint64_t endMonoNs = MonoNanos();
    protocol.AddUInt64(SignalIds::TIME_WALL_END_MS, endWallMs);
    protocol.AddUInt64(SignalIds::TIME_MONO_END_NS, endMonoNs);
    protocol.AddUInt64(SignalIds::TIME_ELAPSED_MONO_NS, endMonoNs >= startMonoNs ? endMonoNs - startMonoNs : 0);

    std::vector<uint8_t> header;
    AppendHeader(header, startWallMs, startMonoNs, challengeHash, nonce);
    return ObfuscationCipher::Seal(header, protocol.Build(), challenge);
}
