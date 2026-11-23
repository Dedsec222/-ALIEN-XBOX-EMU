#include "guest_memory64.hpp"
#include <cassert>
#include <iostream>

int main() {
    using namespace genesis;

    GuestMemory64 memory;

    constexpr uint64_t base = 0x140000000ULL;

    assert(memory.map(
        base, 8192,
        GuestMemory64::Read |
        GuestMemory64::Write |
        GuestMemory64::Execute
    ) == GuestMemory64::Fault::none);

    assert(memory.mappedPages() == 2);
    assert(memory.committedPages() == 0);

    const uint8_t payload[] = {0x48, 0x89, 0xD8};

    assert(memory.write(
        base + 4095, payload
    ) == GuestMemory64::Fault::none);

    assert(memory.committedPages() == 2);

    uint8_t output[3]{};

    assert(memory.read(
        base + 4095, output
    ) == GuestMemory64::Fault::none);

    for (int i = 0; i < 3; ++i)
        assert(output[i] == payload[i]);

    assert(memory.check(
        base + 8192, 1,
        GuestMemory64::Read
    ) == GuestMemory64::Fault::unmapped);

    assert(memory.map(
        base, 4096,
        GuestMemory64::Read
    ) == GuestMemory64::Fault::permission);

    assert(memory.map(
        UINT64_MAX - 4095, 8192,
        GuestMemory64::Read
    ) == GuestMemory64::Fault::overflow);

    std::cout
        << "SCARLETT 64-BIT MEMORY TEST PASSED\n"
        << "Guest image base: 0x"
        << std::hex << base << "\n"
        << std::dec
        << "Mapped pages: " << memory.mappedPages()
        << "\nCommitted pages: "
        << memory.committedPages()
        << "\n";
}
