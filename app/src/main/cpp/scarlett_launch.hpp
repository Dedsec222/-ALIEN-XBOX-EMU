#pragma once
#include "scarlett_cpu64.hpp"
#include "scarlett_pe64.hpp"
#include "scarlett_runtime64.hpp"
#include <sstream>

namespace genesis {
inline std::string launchScarlett(std::span<const uint8_t> file, uint64_t budget) {
    GuestMemory64 memory;
    const auto image=loadScarlettPe(file,memory);
    if (!image.error.empty()) return image.error;
    constexpr uint64_t stack=0x700000000000ull, size=65536, rsp=stack+size-40;
    constexpr uint64_t sentinel=ScarlettImports64::StubBase+0x200;
    ScarlettImports64 imports;
    imports.setImageBase(image.imageBase);
    imports.setExceptionDirectory(image.imageSize,image.exceptionRva,image.exceptionSize);
    if (!imports.install(memory) || !resolveScarlettImports(memory,image,imports)) return "Guest import initialization failed";
    if (memory.map(stack,size,3)!=GuestMemory64::Fault::none ||
        !ScarlettRuntime64::put64(memory,rsp,sentinel) ||
        !ScarlettRuntime64{}.install(memory,image.imageBase,stack,size)) return "Guest stack or TLS initialization failed";
    const auto cpu=executeGuest64(memory,image.entry,budget,rsp,&imports,ScarlettRuntime64::Teb,0,sentinel);
    std::ostringstream out;
    const char* reason="Instruction budget exhausted";
    switch (cpu.exit) {
        case Cpu64Exit::unsupported: reason="Unsupported guest instruction or service";break;
        case Cpu64Exit::memoryFault: reason="Guest memory fault";break;
        case Cpu64Exit::halt: reason="Guest halted";break;
        case Cpu64Exit::breakpoint: reason="Guest breakpoint";break;
        case Cpu64Exit::budget: if(cpu.rip==sentinel) reason="Guest entry returned";break;
    }
    out<<reason<<"\nScarlett V78 interpreter\nRIP 0x"<<std::hex<<cpu.rip<<"\nRAX 0x"<<cpu.gpr[0]
       <<"\nInstructions "<<std::dec<<cpu.steps<<"\nCommitted guest pages "<<memory.committedPages();
    return out.str();
}
}
