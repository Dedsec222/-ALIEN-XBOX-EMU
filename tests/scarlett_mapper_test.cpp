#include "guest_memory64.hpp"
#include <array>
#include <cassert>
#include <iostream>

int main() {
    using namespace genesis;

    GuestMemory64 memory;

    constexpr uint64_t base = 0x140000000ULL;
    constexpr uint64_t entry = base + 0x056A1EC8ULL;

    constexpr uint64_t page = entry & ~uint64_t(4095);

    assert(memory.map(
        page, 4096,
        GuestMemory64::Read | GuestMemory64::Execute
    ) == GuestMemory64::Fault::none);

    const std::array<uint8_t, 3> code{
        0x48, 0x89, 0xD8
    };

    assert(memory.initialize(
        entry, code
    ) == GuestMemory64::Fault::none);

    std::array<uint8_t, 3> result{};

    assert(memory.read(
        entry, result
    ) == GuestMemory64::Fault::none);

    assert(result == code);

    assert(memory.check(
        entry, 3, GuestMemory64::Execute
    ) == GuestMemory64::Fault::none);

    assert(memory.write(
        entry, code
    ) == GuestMemory64::Fault::permission);

    std::cout
        << "SCARLETT EXECUTABLE MEMORY TEST PASSED\n"
        << "Entry address: 0x"
        << std::hex << entry << "\n";
}
