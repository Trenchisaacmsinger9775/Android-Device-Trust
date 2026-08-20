#include "VulkanSignals.hpp"
#include "SignalIds.hpp"

#include <dlfcn.h>
#include <string>
#include <vector>
#include <vulkan/vulkan.h>

typedef VkResult (*CreateInstanceFn)(const VkInstanceCreateInfo*, const VkAllocationCallbacks*, VkInstance*);
typedef void (*DestroyInstanceFn)(VkInstance, const VkAllocationCallbacks*);
typedef VkResult (*EnumeratePhysicalDevicesFn)(VkInstance, uint32_t*, VkPhysicalDevice*);
typedef void (*GetPhysicalDevicePropertiesFn)(VkPhysicalDevice, VkPhysicalDeviceProperties*);

void VulkanSignals::AddVulkanSignals(Protocol::Builder& protocol)
{
    void* library = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (library == nullptr)
    {
        protocol.AddUInt64(SignalIds::VULKAN_STATUS, 1);
        return;
    }

    CreateInstanceFn createInstance = reinterpret_cast<CreateInstanceFn>(dlsym(library, "vkCreateInstance"));
    DestroyInstanceFn destroyInstance = reinterpret_cast<DestroyInstanceFn>(dlsym(library, "vkDestroyInstance"));
    EnumeratePhysicalDevicesFn enumeratePhysicalDevices = reinterpret_cast<EnumeratePhysicalDevicesFn>(dlsym(library, "vkEnumeratePhysicalDevices"));
    GetPhysicalDevicePropertiesFn getPhysicalDeviceProperties = reinterpret_cast<GetPhysicalDevicePropertiesFn>(dlsym(library, "vkGetPhysicalDeviceProperties"));

    if (createInstance == nullptr || destroyInstance == nullptr || enumeratePhysicalDevices == nullptr || getPhysicalDeviceProperties == nullptr)
    {
        protocol.AddUInt64(SignalIds::VULKAN_STATUS, 2);
        dlclose(library);
        return;
    }

    VkApplicationInfo appInfo{};
    appInfo.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    appInfo.pApplicationName = "DeviceCheck";
    appInfo.applicationVersion = 1;
    appInfo.pEngineName = "DeviceCheck";
    appInfo.engineVersion = 1;
    appInfo.apiVersion = VK_API_VERSION_1_0;

    VkInstanceCreateInfo createInfo{};
    createInfo.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    createInfo.pApplicationInfo = &appInfo;

    VkInstance instance = VK_NULL_HANDLE;
    VkResult result = createInstance(&createInfo, nullptr, &instance);
    if (result != VK_SUCCESS || instance == VK_NULL_HANDLE)
    {
        protocol.AddUInt64(SignalIds::VULKAN_STATUS, 3);
        protocol.AddInt64(SignalIds::VULKAN_CREATE_RESULT, static_cast<int64_t>(result));
        dlclose(library);
        return;
    }

    uint32_t count = 0;
    result = enumeratePhysicalDevices(instance, &count, nullptr);
    if (result != VK_SUCCESS || count == 0)
    {
        protocol.AddUInt64(SignalIds::VULKAN_STATUS, 4);
        protocol.AddInt64(SignalIds::VULKAN_ENUMERATE_RESULT, static_cast<int64_t>(result));
        destroyInstance(instance, nullptr);
        dlclose(library);
        return;
    }

    std::vector<VkPhysicalDevice> devices(count);
    result = enumeratePhysicalDevices(instance, &count, devices.data());
    if (result != VK_SUCCESS)
    {
        protocol.AddUInt64(SignalIds::VULKAN_STATUS, 5);
        protocol.AddInt64(SignalIds::VULKAN_ENUMERATE_RESULT, static_cast<int64_t>(result));
        destroyInstance(instance, nullptr);
        dlclose(library);
        return;
    }

    std::string types;
    std::string names;
    for (uint32_t index = 0; index < count; ++index)
    {
        VkPhysicalDeviceProperties properties{};
        getPhysicalDeviceProperties(devices[index], &properties);
        if (!types.empty())
        {
            types += ",";
            names += "\n";
        }
        types += std::to_string(static_cast<int>(properties.deviceType));
        names += properties.deviceName;
    }

    protocol.AddUInt64(SignalIds::VULKAN_STATUS, 0);
    protocol.AddUInt64(SignalIds::VULKAN_DEVICE_COUNT, static_cast<uint64_t>(count));
    protocol.AddString(SignalIds::VULKAN_DEVICE_TYPES, types);
    protocol.AddString(SignalIds::VULKAN_DEVICE_NAMES, names);

    destroyInstance(instance, nullptr);
    dlclose(library);
}
