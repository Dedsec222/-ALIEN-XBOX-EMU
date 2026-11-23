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
    // sub rsp,40; call +1; add rsp,40; int3; ret
    GuestMemory64 stackMem;
    assert(stackMem.map(base,4096,GuestMemory64::Read|GuestMemory64::Execute)==GuestMemory64::Fault::none);
    constexpr uint64_t stack=0x700000000000ull;
    assert(stackMem.map(stack,4096,GuestMemory64::Read|GuestMemory64::Write)==GuestMemory64::Fault::none);
    constexpr std::array<uint8_t,15> calls={
        0x48,0x83,0xec,0x28,0xe8,0x05,0,0,0,
        0x48,0x83,0xc4,0x28,0xcc,0xc3
    };
    // call targets RET at offset 14, then returns to ADD at offset 9.
    assert(stackMem.initialize(base,calls)==GuestMemory64::Fault::none);
    auto called=executeGuest64(stackMem,base,32,stack+4096);
    assert(called.exit==Cpu64Exit::breakpoint);
    assert(called.steps==5);
    assert(called.gpr[4]==stack+4096);
    assert(called.rip==base+14);
    std::cout<<"SCARLETT CPU64 EXECUTION PASSED: RAX="<<s.gpr[0]
             <<" steps="<<s.steps<<" RIP=0x"<<std::hex<<s.rip<<"\n";
}
