#include "guest.hpp"
#include "pe.hpp"
#include "guest_memory.hpp"
#include <vector>
#include <algorithm>
#include <jni.h>
#include <vulkan/vulkan.h>
#include <sstream>

extern "C" JNIEXPORT jstring JNICALL
Java_com_dedsec_alienxbox_MainActivity_diagnostic(JNIEnv* env, jclass) {
    const auto cpu = genesis::interpret(genesis::sum_program, 128);
    const bool passed = cpu.stop == genesis::Stop::breakpoint && cpu.eax == 45 &&
                        cpu.ecx == 0 && cpu.steps == 30;
    std::ostringstream report;
    report << "Native Genesis core loaded\n"
           << "x86-64 guest loop (sum 1 through 9): " << (passed ? "PASS" : "FAIL")
           << "\nEAX: " << cpu.eax << "   ECX: " << cpu.ecx
           << "\nInstructions executed: " << cpu.steps << "\n";
    uint32_t version = VK_API_VERSION_1_0;
    auto query = reinterpret_cast<PFN_vkEnumerateInstanceVersion>(
        vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkEnumerateInstanceVersion"));
    if (!query || query(&version) == VK_SUCCESS)
        report << "Vulkan loader API: " << VK_VERSION_MAJOR(version) << "."
               << VK_VERSION_MINOR(version) << "." << VK_VERSION_PATCH(version) << "\n";
    else report << "Vulkan loader version query failed\n";
    uint32_t count = 0;
    if (vkEnumerateInstanceExtensionProperties(nullptr, &count, nullptr) == VK_SUCCESS)
        report << "Instance extensions: " << count << "\n";
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "Genesis";
    app.apiVersion = VK_API_VERSION_1_0;
    VkInstanceCreateInfo info{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    info.pApplicationInfo = &app;
    VkInstance instance{};
    if (vkCreateInstance(&info, nullptr, &instance) == VK_SUCCESS) {
        uint32_t count = 0;
        if (vkEnumeratePhysicalDevices(instance, &count, nullptr) == VK_SUCCESS && count) {
            std::vector<VkPhysicalDevice> devices(count);
            if (vkEnumeratePhysicalDevices(instance, &count, devices.data()) == VK_SUCCESS) {
                for (const auto gpu : devices) {
                    VkPhysicalDeviceProperties props;
                    vkGetPhysicalDeviceProperties(gpu, &props);
                    report << "GPU: " << props.deviceName << "\nDevice Vulkan: "
                           << VK_VERSION_MAJOR(props.apiVersion) << "." << VK_VERSION_MINOR(props.apiVersion)
                           << "." << VK_VERSION_PATCH(props.apiVersion) << "\n";
                }
            }
        }
        vkDestroyInstance(instance, nullptr);
    } else report << "Vulkan device enumeration unavailable\n";
    return env->NewStringUTF(report.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_dedsec_alienxbox_MainActivity_execute(JNIEnv* env, jclass, jbyteArray program,
                                               jint choice, jint target, jboolean bundled, jint budget) {
    const auto n = env->GetArrayLength(program);
    if (n > 4 * 1024 * 1024) return env->NewStringUTF("Image exceeds 4 MiB.");
    std::vector<uint8_t> file(n);
    if (n) env->GetByteArrayRegion(program, 0, n, reinterpret_cast<jbyte*>(file.data()));
    if (env->ExceptionCheck()) return nullptr;
    const auto mapped = genesis::mapPe(file);
    if (mapped.error) return env->NewStringUTF(mapped.error);
    const auto process = genesis::prepareProcess(file);
    if (process.error) return env->NewStringUTF(process.error);
    const auto cpu = genesis::interpret(mapped.bytes, std::clamp(budget, 1000, 100000), process.entry, choice, target);
    std::ostringstream report;
    switch (cpu.stop) {
    case genesis::Stop::breakpoint:
        if (bundled) report << (cpu.eax == 1 ? "Found the alien!" : "Missed! It was behind door ") ;
        if (bundled && cpu.eax != 1) report << target;
        report << "\nGuest breakpoint"; break;
    case genesis::Stop::budget: report << "Instruction budget exhausted"; break;
    case genesis::Stop::unsupported: report << "Unsupported instruction"; break;
    case genesis::Stop::truncated: report << "Truncated instruction"; break;
    case genesis::Stop::invalidTarget: report << "Invalid branch target"; break;
    }
    report << "\nRIP (RVA) 0x" << std::hex << cpu.rip << std::dec
           << "   EAX " << cpu.eax << "\nInstructions " << cpu.steps;
    return env->NewStringUTF(report.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_dedsec_alienxbox_MainActivity_validate(JNIEnv* env, jclass, jbyteArray program) {
    const auto size = env->GetArrayLength(program);
    if (size > 4 * 1024 * 1024) return env->NewStringUTF("Image exceeds 4 MiB.");
    std::vector<uint8_t> data(size);
    if (size) env->GetByteArrayRegion(program, 0, size, reinterpret_cast<jbyte*>(data.data()));
    if (env->ExceptionCheck()) return nullptr;
    auto process = genesis::prepareProcess(data);
    return env->NewStringUTF(process.error ? process.error : "");
}
