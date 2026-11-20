#include "guest.hpp"
#include "pe.hpp"
#include <vector>
#include <jni.h>
#include <vulkan/vulkan.h>
#include <sstream>

extern "C" JNIEXPORT jstring JNICALL
Java_com_dedsec_alienxbox_MainActivity_diagnostic(JNIEnv* env, jclass) {
    const auto cpu = genesis::interpret(genesis::sum_program, 128);
    const bool passed = cpu.stop == genesis::Stop::breakpoint && cpu.eax == 45 &&
                        cpu.ecx == 0 && cpu.steps == 30;
    std::ostringstream report;
    report << "ARM64 native core loaded\n"
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
    return env->NewStringUTF(report.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_dedsec_alienxbox_MainActivity_execute(JNIEnv* env, jclass, jbyteArray program,
                                               jint choice, jint target, jboolean bundled) {
    const auto n = env->GetArrayLength(program);
    if (n > 4 * 1024 * 1024) return env->NewStringUTF("Image exceeds 4 MiB.");
    std::vector<uint8_t> file(n);
    if (n) env->GetByteArrayRegion(program, 0, n, reinterpret_cast<jbyte*>(file.data()));
    if (env->ExceptionCheck()) return nullptr;
    const auto image = genesis::loadPe(file);
    if (image.error) return env->NewStringUTF(image.error);
    const auto cpu = genesis::interpret(image.code, 100000, image.entry, choice, target);
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
    report << "\nRIP (RVA) 0x" << std::hex << image.sectionRva+cpu.rip << std::dec
           << "   EAX " << cpu.eax << "\nInstructions " << cpu.steps;
    return env->NewStringUTF(report.str().c_str());
}
