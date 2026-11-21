#include "cpu64.hpp"
#include <cassert>
#include <iostream>
int main() {
    using namespace genesis;
    GuestMemory mem(3 * 4096);
    assert(mem.protect(0, 4096, Read | Execute) == MemoryFault::none);
    assert(mem.protect(4096, 4096, Read | Write) == MemoryFault::none);
    const uint8_t program[] = {
        0x48,0xb8,0x78,0x56,0x34,0x12,0,0,0,0, // mov rax, 0x12345678
        0x50, // push rax
        0x48,0x31,0xc0, // xor rax, rax
        0x5b, // pop rbx
        0x48,0x89,0xd8, // mov rax, rbx
        0x48,0x39,0xd8, // cmp rax, rbx
        0x75,0x02, // jnz +2 (not taken)
        0x90, // nop
        0xcc  // int3
    };
    assert(mem.initialize(0, program) == MemoryFault::none);
    auto result = executeGuest(mem, 0, 8192);
    assert(result.exit == CpuExit::breakpoint);
    assert(result.gpr[0] == 0x12345678);
    assert(result.gpr[3] == 0x12345678);
    assert(result.gpr[4] == 8192);
    assert(result.steps == 9);
    const uint8_t bad[] = {0x0f,0x05};
    assert(mem.initialize(0, bad) == MemoryFault::none);
    assert(executeGuest(mem, 0, 8192).exit == CpuExit::unsupported);
    assert(executeGuest(mem, 4096, 8192).exit == CpuExit::memoryFault);
    std::cout << "Protected x86-64 register/stack/branch tests passed.\n";
}
