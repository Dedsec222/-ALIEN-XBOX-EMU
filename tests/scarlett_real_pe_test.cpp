#include "scarlett_pe64.hpp"
#include <array>
#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) return 2;

    std::ifstream stream(argv[1], std::ios::binary);

    if (!stream) {
        std::cerr << "Cannot open executable\n";
        return 1;
    }

    std::vector<uint8_t> file(
        (std::istreambuf_iterator<char>(stream)),
        std::istreambuf_iterator<char>());

    genesis::GuestMemory64 memory;

    auto result = genesis::loadScarlettPe(file, memory);

    if (!result.error.empty()) {
        std::cerr << "Loader error: " << result.error << '\n';
        return 1;
    }

    std::array<uint8_t, 16> entryBytes{};

    if (memory.read(result.entry, entryBytes) !=
        genesis::GuestMemory64::Fault::none) {
        std::cerr << "Cannot read entry point\n";
        return 1;
    }

    if (memory.check(result.entry, 16,
            genesis::GuestMemory64::Execute) !=
        genesis::GuestMemory64::Fault::none) {
        std::cerr << "Entry is not executable\n";
        return 1;
    }

    std::cout << "SCARLETT PE MAPPING PASSED\n"
              << "Image base: 0x" << std::hex << result.imageBase
              << "\nEntry: 0x" << result.entry
              << std::dec
              << "\nSections: " << result.sections
              << "\nMapped pages: " << memory.mappedPages()
              << "\nCommitted pages: " << memory.committedPages()
              << "\nEntry bytes:";

    for (auto b : entryBytes)
        std::cout << ' ' << std::hex << unsigned(b);

    std::cout << '\n';
}
