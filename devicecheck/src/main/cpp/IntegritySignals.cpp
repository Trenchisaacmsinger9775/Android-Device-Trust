#include "IntegritySignals.hpp"
#include "AttestationKeys.hpp"
#include "SignalIds.hpp"

#include <elf.h>
#include <link.h>
#include <cstdint>
#include <vector>
#include <zlib.h>

struct TextCrcFinder
{
    uintptr_t target;
    uint64_t hash;
    uint32_t crc;
    uint64_t size;
    bool found;
};

static int TextCrcCallback(dl_phdr_info* info, size_t, void* data)
{
    TextCrcFinder* finder = static_cast<TextCrcFinder*>(data);
    uintptr_t base = static_cast<uintptr_t>(info->dlpi_addr);
    bool ownsTarget = false;

    for (int index = 0; index < info->dlpi_phnum; ++index)
    {
        const ElfW(Phdr)* header = &info->dlpi_phdr[index];
        if (header->p_type != PT_LOAD)
        {
            continue;
        }
        uintptr_t start = base + header->p_vaddr;
        uintptr_t end = start + header->p_memsz;
        if (finder->target >= start && finder->target < end)
        {
            ownsTarget = true;
            break;
        }
    }

    if (!ownsTarget) return 0;

    for (int index = 0; index < info->dlpi_phnum; ++index)
    {
        const ElfW(Phdr)* header = &info->dlpi_phdr[index];
        if (header->p_type != PT_LOAD || (header->p_flags & PF_X) == 0)
        {
            continue;
        }
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(base + header->p_vaddr);
        std::vector<uint8_t> data(bytes, bytes + header->p_filesz);
        finder->hash = AttestationKeys::Hash64(data);
        finder->crc = static_cast<uint32_t>(crc32(0L, bytes, static_cast<uInt>(header->p_filesz)));
        finder->size = static_cast<uint64_t>(header->p_filesz);
        finder->found = true;
        return 1;
    }

    return 1;
}

void IntegritySignals::AddIntegritySignals(Protocol::Builder& protocol)
{
    TextCrcFinder finder{};
    finder.target = reinterpret_cast<uintptr_t>(&IntegritySignals::AddIntegritySignals);
    dl_iterate_phdr(TextCrcCallback, &finder);
    protocol.AddUInt64(SignalIds::INTEGRITY_TEXT_HASH64, finder.hash);
    protocol.AddUInt64(SignalIds::INTEGRITY_TEXT_CRC32, static_cast<uint64_t>(finder.crc));
    protocol.AddUInt64(SignalIds::INTEGRITY_TEXT_SIZE, finder.size);
    protocol.AddUInt64(SignalIds::INTEGRITY_TEXT_FOUND, finder.found ? 1 : 0);
}
