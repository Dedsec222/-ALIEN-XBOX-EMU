#include "guest.hpp"
#include "scarlett_probe.hpp"
#include "scarlett_launch.hpp"
#include "vulkan_transfer.hpp"
#include <sys/resource.h>
#include "pe.hpp"
#include "guest_memory.hpp"
#include "cpu64.hpp"
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
    report << genesis::scarlettProbe() << "\n";
    struct rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage)==0) report << "Process peak RSS: " << usage.ru_maxrss << " KiB\n";
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
                    VkPhysicalDeviceMemoryProperties heaps{};
                    vkGetPhysicalDeviceMemoryProperties(gpu,&heaps);
                    for (uint32_t h=0;h<heaps.memoryHeapCount;++h)
                        report<<"Heap "<<h<<": "<<(heaps.memoryHeaps[h].size>>20)<<" MiB"<<
                            ((heaps.memoryHeaps[h].flags&VK_MEMORY_HEAP_DEVICE_LOCAL_BIT)?" device local":"")<<"\n";
                    uint32_t families=0;
                    vkGetPhysicalDeviceQueueFamilyProperties(gpu,&families,nullptr);
                    std::vector<VkQueueFamilyProperties> queues(families);
                    vkGetPhysicalDeviceQueueFamilyProperties(gpu,&families,queues.data());
                    for (uint32_t q=0;q<families;++q)
                        report<<"Queue "<<q<<": "<<queues[q].queueCount<<" flags 0x"<<std::hex<<queues[q].queueFlags<<std::dec<<"\n";
                    for (uint32_t q=0;q<families;++q) {
                        if (queues[q].queueCount && (queues[q].queueFlags&(VK_QUEUE_GRAPHICS_BIT|VK_QUEUE_COMPUTE_BIT|VK_QUEUE_TRANSFER_BIT))) {
                            report<<"Vulkan transfer readback: "<<genesis::verifyTransfer(gpu,q)<<"\n";
                            break;
                        }
                    }
                    VkPhysicalDeviceFeatures features;
                    vkGetPhysicalDeviceFeatures(gpu,&features);
                    report<<"Sampled block compression: BC "<<features.textureCompressionBC
                          <<", ASTC LDR "<<features.textureCompressionASTC_LDR<<", ETC2 "<<features.textureCompressionETC2<<"\n";
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
    auto process = genesis::prepareProcess(file);
    if (process.error) return env->NewStringUTF(process.error);
    // Preserve the original bundled door-game ABI. External freestanding
    // homebrew uses the protected-memory CPU core with a real guest stack.
    if (!bundled) {
        auto state = genesis::executeGuest(process.memory, process.entry,
                                          process.stackTop,
                                          static_cast<uint64_t>(std::clamp(budget, 1000, 100000)));
        std::ostringstream out;
        switch (state.exit) {
        case genesis::CpuExit::breakpoint: out << "Guest breakpoint"; break;
        case genesis::CpuExit::halt: out << "Guest halted"; break;
        case genesis::CpuExit::unsupported: out << "Unsupported guest instruction"; break;
        case genesis::CpuExit::memoryFault: out << "Guest memory protection fault"; break;
        case genesis::CpuExit::budget: out << "Instruction budget exhausted"; break;
        }
        out << "\\nRIP 0x" << std::hex << state.rip
            << "\\nRAX 0x" << state.gpr[0] << std::dec
            << "\\nInstructions " << state.steps;
        return env->NewStringUTF(out.str().c_str());
    }
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
Java_com_dedsec_alienxbox_MainActivity_mappedImage(JNIEnv* env,jclass,jobject buffer,jboolean run,jint budget,jboolean translate) {
    const auto length=env->GetDirectBufferCapacity(buffer);
    auto data=static_cast<const uint8_t*>(env->GetDirectBufferAddress(buffer));
    if (!data || length<=0 || length>(256LL<<20)) return env->NewStringUTF("Invalid mapped PE");
    const std::span<const uint8_t> file(data,static_cast<size_t>(length));
    const auto info=genesis::inspectPe(file);
    if (info.error) return env->NewStringUTF(info.error);
    if (!run) return env->NewStringUTF("");
    try {
        if (!info.imageBase) {
            auto legacy=genesis::prepareProcess(file);
            if (legacy.error) return env->NewStringUTF(legacy.error);
            auto state=genesis::executeGuest(legacy.memory,legacy.entry,legacy.stackTop,std::clamp(budget,1000,100000));
            std::ostringstream result;
            const char* reasons[]={"Guest breakpoint","Guest halted","Unsupported guest instruction","Guest memory protection fault","Instruction budget exhausted"};
            result<<reasons[static_cast<unsigned>(state.exit)]<<"\nRIP 0x"<<std::hex<<state.rip<<"\nRAX 0x"<<state.gpr[0]<<"\nInstructions "<<std::dec<<state.steps;
            return env->NewStringUTF(result.str().c_str());
        }
        const auto result=genesis::launchScarlett(file,std::clamp(budget,1000,10000000),translate);
        return env->NewStringUTF(result.c_str());
    } catch (const std::bad_alloc&) {return env->NewStringUTF("Host memory exhausted while mapping guest");}
}
