#pragma once
#include <cstddef>
#include <cstdint>
#include <span>

namespace genesis {
enum class Stop { breakpoint, truncated, unsupported, invalidTarget, budget };
struct Result {
    Stop stop;
    uint32_t eax = 0, ecx = 0;
    size_t rip = 0, steps = 0;
};
// Flat, read-only code starting at guest address zero. Only ZF is modeled.
Result interpret(std::span<const uint8_t> code, size_t budget, size_t entry = 0,
                 uint32_t input = 0, uint32_t target = 0);
inline constexpr uint8_t sum_program[] = {
    0xb8, 0, 0, 0, 0,       // mov eax, 0
    0xb9, 9, 0, 0, 0,       // mov ecx, 9
    0x01, 0xc8,             // add eax, ecx
    0xff, 0xc9,             // dec ecx
    0x75, 0xfa,             // jnz -6
    0xcc                    // int3 (return control to host)
};
}
