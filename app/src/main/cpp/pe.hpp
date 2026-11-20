#pragma once
#include "guest.hpp"

namespace genesis {
struct Image {
    std::span<const uint8_t> code{};
    uint32_t sectionRva = 0;
    size_t entry = 0;
    const char* error = nullptr;
};
Image loadPe(std::span<const uint8_t> file);
}
