#include "ProcSignals.hpp"
#include "FileSignals.hpp"
#include "AttestationKeys.hpp"
#include "SignalIds.hpp"

#include <android/api-level.h>
#include <sys/system_properties.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

static std::string GetProp(const char* name)
{
    char value[PROP_VALUE_MAX];
    int length = __system_property_get(name, value);
    if (length <= 0) return std::string();

    return std::string(value, static_cast<size_t>(length));
}

static void AddProperty(Protocol::Builder& protocol, uint64_t fieldId, const char* name)
{
    protocol.AddString(fieldId, GetProp(name));
}

static uint32_t Crc32Names(const std::string& text)
{
    uint32_t crc = 0x811C9DC5u;
    for (char character : text)
    {
        crc ^= static_cast<uint8_t>(character);
        crc *= 16777619u;
    }
    return crc;
}

static void AddEnvironment(Protocol::Builder& protocol)
{
    extern char** environ;
    std::vector<uint8_t> combined;
    uint64_t count = 0;
    if (environ == nullptr)
    {
        protocol.AddUInt64(SignalIds::ENV_COUNT, 0);
        protocol.AddUInt64(SignalIds::ENV_HASH64, 0);
        return;
    }
    for (int index = 0; environ[index] != nullptr && index < 128; ++index)
    {
        std::string entry = environ[index];
        combined.insert(combined.end(), entry.begin(), entry.end());
        combined.push_back(0);
        ++count;
    }
    protocol.AddUInt64(SignalIds::ENV_COUNT, count);
    protocol.AddUInt64(SignalIds::ENV_HASH64, AttestationKeys::Hash64(combined));
}

static void AddLibraryDigest(Protocol::Builder& protocol)
{
    std::string maps = FileSignals::ReadFile("/proc/self/maps", 1024 * 1024);
    int count = 0;
    std::string names;
    size_t position = 0;
    while (position < maps.size())
    {
        size_t end = maps.find('\n', position);
        std::string line = maps.substr(position, end == std::string::npos ? std::string::npos : end - position);
        position = end == std::string::npos ? maps.size() : end + 1;

        size_t so = line.find(".so");
        if (so == std::string::npos)
        {
            continue;
        }
        size_t slash = line.rfind('/', so);
        if (slash == std::string::npos)
        {
            continue;
        }
        std::string name = line.substr(slash + 1, so - slash + 2);
        if (names.find(name + "\n") != std::string::npos)
        {
            continue;
        }
        names += name;
        names += '\n';
        ++count;
    }
    protocol.AddUInt64(SignalIds::MAPS_LIBRARY_COUNT, static_cast<uint64_t>(count));
    protocol.AddUInt64(SignalIds::MAPS_LIBRARY_NAMES_DIGEST, static_cast<uint64_t>(Crc32Names(names)));
}

void ProcSignals::AddProcSignals(Protocol::Builder& protocol)
{
    struct utsname systemInfo;
    if (uname(&systemInfo) == 0)
    {
        protocol.AddString(SignalIds::UNAME_SYSNAME, systemInfo.sysname);
        protocol.AddString(SignalIds::UNAME_RELEASE, systemInfo.release);
        protocol.AddString(SignalIds::UNAME_VERSION, systemInfo.version);
        protocol.AddString(SignalIds::UNAME_MACHINE, systemInfo.machine);
    }

    protocol.AddUInt64(SignalIds::PROCESS_UID, static_cast<uint64_t>(getuid()));
    protocol.AddUInt64(SignalIds::PROCESS_PID, static_cast<uint64_t>(getpid()));
    protocol.AddUInt64(SignalIds::PROCESS_API_LEVEL, static_cast<uint64_t>(android_get_device_api_level()));
    AddEnvironment(protocol);
    AddLibraryDigest(protocol);

    AddProperty(protocol, SignalIds::PROP_FIRST_API_LEVEL, "ro.product.first_api_level");
    AddProperty(protocol, SignalIds::PROP_SECURITY_PATCH, "ro.build.version.security_patch");
    AddProperty(protocol, SignalIds::PROP_CPU_ABILIST, "ro.product.cpu.abilist");
    AddProperty(protocol, SignalIds::PROP_ISA_ARM, "ro.dalvik.vm.isa.arm");
    AddProperty(protocol, SignalIds::PROP_ISA_ARM64, "ro.dalvik.vm.isa.arm64");
    AddProperty(protocol, SignalIds::PROP_NATIVE_BRIDGE_EXEC, "ro.enable.native.bridge.exec");
    AddProperty(protocol, SignalIds::PROP_NATIVE_BRIDGE, "ro.dalvik.vm.native.bridge");
    AddProperty(protocol, SignalIds::PROP_OPENGLES_VERSION, "ro.opengles.version");
    AddProperty(protocol, SignalIds::PROP_PRODUCT_BOARD, "ro.product.board");
    AddProperty(protocol, SignalIds::PROP_SOC_MODEL, "ro.soc.model");
    AddProperty(protocol, SignalIds::PROP_SOC_MANUFACTURER, "ro.soc.manufacturer");
}
