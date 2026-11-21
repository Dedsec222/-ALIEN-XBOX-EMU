#pragma once
#include "guest.hpp"

namespace genesis {
struct Image {
    std::span<const uint8_t> code{};
    uint32_t sectionRva = 0;
    size_t entry = 0;
    const char* error = nullptr;
};
// Metadata-only PE32+ inspection; never executes untrusted bytes.
struct PeInfo {
    uint16_t sections = 0;
    uint32_t entryRva = 0;
    uint32_t imageSize = 0;
    uint32_t importsRva = 0;
    uint32_t relocationsRva = 0;
    const char* error = nullptr;
};
PeInfo inspectPe(std::span<const uint8_t> file);
Image loadPe(std::span<const uint8_t> file);
}
