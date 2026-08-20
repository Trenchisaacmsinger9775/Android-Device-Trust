#include "FileSignals.hpp"
#include "AttestationKeys.hpp"
#include "Compression.hpp"
#include "SignalIds.hpp"

#include <fcntl.h>
#include <unistd.h>

std::string FileSignals::ReadFile(const char* path, size_t maxBytes)
{
    std::vector<uint8_t> bytes;
    if (!ReadFileBytes(path, maxBytes, bytes)) return std::string();

    return std::string(bytes.begin(), bytes.end());
}

bool FileSignals::ReadFileBytes(const char* path, size_t maxBytes, std::vector<uint8_t>& out)
{
    out.clear();
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;

    uint8_t buffer[4096];
    while (out.size() < maxBytes)
    {
        size_t remaining = maxBytes - out.size();
        size_t wanted = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        ssize_t bytesRead = read(fd, buffer, wanted);
        if (bytesRead <= 0)
        {
            break;
        }
        out.insert(out.end(), buffer, buffer + bytesRead);
    }

    close(fd);
    return !out.empty();
}

static void AddCompressedFile(Protocol::Builder& protocol, uint64_t fieldId, const char* path, size_t maxBytes)
{
    std::vector<uint8_t> raw;
    std::vector<uint8_t> compressed;
    if (!FileSignals::ReadFileBytes(path, maxBytes, raw))
    {
        protocol.AddBytes(fieldId, raw, Protocol::FLAG_ABSENT);
        return;
    }
    if (!Compression::ZlibCompress(raw, compressed))
    {
        protocol.AddBytes(fieldId, raw);
        return;
    }
    protocol.AddBytes(fieldId, compressed, Protocol::FLAG_ZLIB);
}

static void AddHashedFile(Protocol::Builder& protocol, uint64_t fieldId, const char* path, size_t maxBytes)
{
    std::vector<uint8_t> raw;
    if (!FileSignals::ReadFileBytes(path, maxBytes, raw))
    {
        protocol.AddHashedBytes(fieldId, raw, false);
        return;
    }

    protocol.AddHashedBytes(fieldId, raw, true);
}

void FileSignals::AddFileSignals(Protocol::Builder& protocol)
{
    AddCompressedFile(protocol, SignalIds::FILE_MAPS, "/proc/self/maps", 1024 * 1024);
    AddCompressedFile(protocol, SignalIds::FILE_CPUINFO, "/proc/cpuinfo", 256 * 1024);
    AddCompressedFile(protocol, SignalIds::FILE_MOUNTS, "/proc/mounts", 256 * 1024);

    AddHashedFile(protocol, SignalIds::FILE_STATUS_HASH, "/proc/self/status", 64 * 1024);
    AddHashedFile(protocol, SignalIds::FILE_STAT_HASH, "/proc/self/stat", 16 * 1024);
    AddHashedFile(protocol, SignalIds::FILE_SELF_CGROUP_HASH, "/proc/self/cgroup", 64 * 1024);
    AddHashedFile(protocol, SignalIds::FILE_MEMINFO_HASH, "/proc/meminfo", 64 * 1024);
}
