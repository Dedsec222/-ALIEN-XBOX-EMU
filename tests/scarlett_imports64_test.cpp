#include "scarlett_imports64.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>

int main() {
    genesis::GuestMemory64 memory;
    genesis::ScarlettImports64 imports;

    assert(imports.install(memory));

    const uint64_t stub = imports.registerImport(
        "api-ms-win-core-sysinfo-l1-1-0.dll",
        "GetSystemTimeAsFileTime"
    );

    assert(stub != 0);
    assert(imports.contains(stub));

    constexpr uint64_t output = 0x700000000000ull;

    assert(memory.map(
        output, 4096,
        genesis::GuestMemory64::Read |
        genesis::GuestMemory64::Write
    ) == genesis::GuestMemory64::Fault::none);

    uint64_t rax=0;
    assert(imports.dispatch(stub, memory, output, rax));

    std::array<uint8_t,8> result{};
    assert(memory.read(output, result) ==
           genesis::GuestMemory64::Fault::none);

    uint64_t ticks = 0;
    for (unsigned i = 0; i < 8; ++i)
        ticks |= uint64_t(result[i]) << (i * 8);

    assert(ticks > 116444736000000000ULL);

    std::cout << "SCARLETT IMPORT TEST PASSED\n";
    std::cout << "Stub: 0x" << std::hex << stub << "\n";
    std::cout << "FILETIME: " << std::dec << ticks << "\n";
}
