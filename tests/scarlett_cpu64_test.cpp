#include "scarlett_cpu64.hpp"
#include <array>
#include <cassert>
#include <iostream>

int main() {
    using namespace genesis;
    GuestMemory64 mem;
    constexpr uint64_t base=0x140000000ull;
    assert(mem.map(base,4096,GuestMemory64::Read|GuestMemory64::Execute)==GuestMemory64::Fault::none);
    // mov rax,42; mov rcx,8; add rax,rcx; int3
    constexpr std::array<uint8_t,24> program={
        0x48,0xb8,42,0,0,0,0,0,0,0,
        0x48,0xb9,8,0,0,0,0,0,0,0,
        0x48,0x01,0xc8,0xcc
    };
    assert(mem.initialize(base,program)==GuestMemory64::Fault::none);
    auto s=executeGuest64(mem,base);
    assert(s.exit==Cpu64Exit::breakpoint);
    assert(s.gpr[0]==50 && s.gpr[1]==8 && s.steps==4);
    assert(s.rip==base+program.size());
    auto limited=executeGuest64(mem,base,2);
    assert(limited.exit==Cpu64Exit::budget && limited.steps==2);
    assert(limited.gpr[0]==42);
    auto fault=executeGuest64(mem,base+4096);
    assert(fault.exit==Cpu64Exit::memoryFault);
    std::cout<<"SCARLETT CPU64 EXECUTION PASSED: RAX="<<s.gpr[0]
             <<" steps="<<s.steps<<" RIP=0x"<<std::hex<<s.rip<<"\n";
}
