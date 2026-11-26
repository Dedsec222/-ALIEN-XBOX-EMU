#include "direct_pe_loader.hpp"

#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr <<
            "Usage: direct_pe_probe <exe> [base]\n";
        return 1;
    }

    try {
        std::ifstream file(
            argv[1],
            std::ios::binary | std::ios::ate);

        if (!file)
            throw std::runtime_error("Open failed");

        const auto size = file.tellg();

        if (size <= 0 ||
            size > std::streamoff(2ULL << 30))
            throw std::runtime_error(
                "Invalid file size");

        std::vector<std::byte> bytes(
            static_cast<size_t>(size));

        file.seekg(0);

        if (!file.read(
            reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(
                bytes.size())))
            throw std::runtime_error("Read failed");

        auto pe = alien::Pe64Image::parse(bytes);

        const size_t sections = pe.sections.size();

        std::vector<std::byte>().swap(bytes);

        uint64_t requested = 0;

        if (argc == 3)
            requested = std::stoull(
                argv[2], nullptr, 0);

        alien::DirectPeLoader loader;

        loader.load(std::move(pe), requested);

        std::cout << std::hex
            << "Mapped base: 0x" << loader.base()
            << "\nEntry VA: 0x" << loader.entry()
            << "\nImage size: 0x" << loader.size()
            << '\n';

        std::cout << "Entry bytes: ";

        for (unsigned i = 0; i < 16; ++i) {
            uint8_t value = 0;

            if (!loader.fetchByte(
                loader.entry() + i, value))
                break;

            std::cout << std::setw(2)
                << std::setfill('0')
                << unsigned(value) << ' ';
        }

        std::cout << std::dec
            << "\nSections: " << sections
            << "\nHost page size: "
            << alien::DirectGuestMemory::pageSize()
            << "\nResolved imports: "
            << loader.imports().resolved
            << "\nUnresolved imports: "
            << loader.imports().unresolved.size()
            << '\n';

        const uint8_t test = 0;

        if (loader.write(
            loader.entry(), &test, 1))
            throw std::runtime_error(
                "Unexpected writable entry page");

        std::cout <<
            "Entry write protection: PASS\n"
            "DIRECT PE MAPPING PASSED\n"
            "Guest execution: NOT ATTEMPTED\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 2;
    }
}
