
#include "pe64_image.hpp"

#include <fstream>
#include <iostream>
#include <limits>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: pe_probe <PE32+ file>\n";
        return 1;
    }

    try {
        std::ifstream file(
            argv[1],
            std::ios::binary | std::ios::ate
        );

        if (!file)
            throw std::runtime_error("Cannot open file");

        const auto size = file.tellg();

        if (size <= 0)
            throw std::runtime_error("Invalid file size");

        std::vector<std::byte> bytes(
            static_cast<size_t>(size)
        );

        file.seekg(0);

        if (!file.read(
            reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size())
        ))
            throw std::runtime_error("File read failed");

        auto pe = alien::Pe64Image::parse(bytes);

        std::cout << std::hex;

        std::cout
            << "Image base: 0x" << pe.image_base
            << "\nEntry RVA: 0x" << pe.entry_rva
            << "\nImage size: 0x" << pe.image_size
            << '\n';

        for (const auto& s : pe.sections) {
            std::cout
                << "SECTION " << s.name
                << " RVA=0x" << s.virtual_address
                << " VSIZE=0x" << s.virtual_size
                << " "
                << (s.readable() ? 'R' : '-')
                << (s.writable() ? 'W' : '-')
                << (s.executable() ? 'X' : '-')
                << '\n';
        }

        for (const auto& imp : pe.imports) {
            std::cout << imp.module << '!';

            if (imp.by_ordinal)
                std::cout << '#' << std::dec
                          << imp.ordinal << std::hex;
            else
                std::cout << imp.symbol;

            std::cout
                << " IAT=0x"
                << pe.image_base + imp.iat_rva
                << '\n';
        }

        std::cout << std::dec
                  << "Total imports: "
                  << pe.imports.size()
                  << '\n';

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 2;
    }
}

