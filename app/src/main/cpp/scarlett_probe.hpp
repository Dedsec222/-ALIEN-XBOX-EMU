#pragma once
#include "scarlett_cpu64.hpp"
#include <sstream>

namespace genesis {
inline std::string scarlettProbe() {
    GuestMemory64 memory;
    constexpr uint64_t entry=0x1000;
    // mov edi, 12345678h / bswap edi / int3
    constexpr std::array<uint8_t,8> code={0xbf,0x78,0x56,0x34,0x12,0x0f,0xcf,0xcc};
    if (memory.map(entry,4096,GuestMemory64::Execute)!=GuestMemory64::Fault::none ||
        memory.initialize(entry,code)!=GuestMemory64::Fault::none) return "Scarlett probe mapping failed";
    const auto state=executeGuest64(memory,entry,3);
    std::ostringstream message;
    message<<"Scarlett V78 BSWAP EDI: "<<(state.exit==Cpu64Exit::breakpoint &&
        state.gpr[7]==0x78563412 && state.steps==3 ? "PASS" : "FAIL")
        <<" (EDI 0x"<<std::hex<<state.gpr[7]<<")";
    return message.str();
}
}
