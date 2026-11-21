#include "guest_memory.hpp"
#include <cassert>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <vector>
#include <iostream>

int main() {
    using namespace genesis;
    GuestMemory mem(3 * GuestMemory::pageSize);
    assert(mem.size() == 3 * GuestMemory::pageSize);
    assert(mem.protect(0, 4096, Read | Execute) == MemoryFault::none);
    assert(mem.protect(4096, 4096, Read | Write) == MemoryFault::none);
    assert(mem.protect(8192, 4096, Read) == MemoryFault::none);
    assert(mem.store32(4096, 0x12345678) == MemoryFault::none);
    uint32_t value = 0;
    assert(mem.load32(4096, value) == MemoryFault::none && value == 0x12345678);
    assert(mem.store32(0, 9) == MemoryFault::permission);
    assert(mem.store32(8192, 9) == MemoryFault::permission);
    assert(mem.store32(4094, 9) == MemoryFault::permission);
    assert(mem.load32(12287, value) == MemoryFault::overflow);
    assert(mem.check(0, 1, Execute) == MemoryFault::none);
    assert(mem.check(4096, 1, Execute) == MemoryFault::permission);
    assert(mem.check(0xffffffffu, 4, Read) == MemoryFault::overflow);
    assert(mem.protect(1, 4096, Read) == MemoryFault::overflow);
    assert(mem.protect(0, 4096, 8) == MemoryFault::permission);
    assert(mem.initialize(0, std::span<const uint8_t>{}) == MemoryFault::none);
    GuestMemory invalid(4095);
    assert(invalid.size() == 0);
    std::ifstream source("app/src/main/assets/doors.exe", std::ios::binary);
    assert(source);
    std::vector<uint8_t> file(std::istreambuf_iterator<char>(source), {});
    auto process = prepareProcess(file);
    assert(!process.error);
    assert(process.entry != 0);
    assert(process.stackTop == GuestMemory::maxSize);
    assert(process.memory.check(process.entry, 1, Execute) == MemoryFault::none);
    assert(process.memory.check(process.stackTop - 4, 4, Write) == MemoryFault::none);
    assert(process.memory.check(process.stackTop - 17 * 4096, 4, Read) == MemoryFault::unmapped);
    assert(process.memory.store32(process.entry, 0) == MemoryFault::permission);
    file[0] = 0;
    assert(prepareProcess(file).error);
    std::cout << "Guest memory permissions, stack isolation and PE process tests passed.\n";
}
