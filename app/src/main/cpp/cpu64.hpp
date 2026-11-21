#pragma once
#include "guest_memory.hpp"
#include <array>
#include <cstdint>
#include <limits>

namespace genesis {
// Independent bounded x86-64 guest execution core. This is a deliberately
// small, auditable interpreter, not an Xbox CPU/JIT implementation.
enum class CpuExit { breakpoint, halt, unsupported, memoryFault, budget };
struct CpuState {
    std::array<uint64_t, 16> gpr{};
    uint64_t rip = 0;
    uint64_t steps = 0;
    bool zf = false;
    CpuExit exit = CpuExit::budget;
};
inline CpuState executeGuest(GuestMemory& mem, uint32_t entry,
                            uint32_t stackTop, uint64_t budget = 100000) {
    CpuState s{};
    s.rip = entry;
    s.gpr[4] = stackTop; // RSP
    auto read = [&](uint64_t address, uint8_t& value) {
        if (address > UINT32_MAX) return false;
        return mem.fetch(static_cast<uint32_t>(address), std::span<uint8_t>(&value, 1)) == MemoryFault::none;
    };
    auto fetch32 = [&](uint64_t address, uint32_t& value) {
        value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            uint8_t b{};
            if (!read(address + i, b)) return false;
            value |= uint32_t(b) << (8 * i);
        }
        return true;
    };
    for (; s.steps < budget; ++s.steps) {
        uint64_t pc = s.rip;
        uint8_t op{}, rex = 0;
        if (!read(pc++, op)) { s.exit = CpuExit::memoryFault; break; }
        if (op >= 0x40 && op <= 0x4f) {
            rex = op;
            if (!read(pc++, op)) { s.exit = CpuExit::memoryFault; break; }
        }
        const bool wide = (rex & 8) != 0;
        if (op == 0xcc || op == 0xf4) {
            s.rip = pc;
            s.exit = op == 0xcc ? CpuExit::breakpoint : CpuExit::halt;
            ++s.steps;
            break;
        }
        if (op == 0x90) { s.rip = pc; continue; }
        if (op >= 0xb8 && op <= 0xbf) {
            const unsigned reg = (op - 0xb8) + ((rex & 1) ? 8 : 0);
            uint32_t low{};
            if (!fetch32(pc, low)) { s.exit = CpuExit::memoryFault; break; }
            pc += 4;
            if (wide) {
                uint32_t high{};
                if (!fetch32(pc, high)) { s.exit = CpuExit::memoryFault; break; }
                pc += 4;
                s.gpr[reg] = uint64_t(low) | (uint64_t(high) << 32);
            } else s.gpr[reg] = low;
            s.rip = pc;
            continue;
        }
        if (op >= 0x50 && op <= 0x5f) {
            const unsigned reg = (op & 7) + ((rex & 1) ? 8 : 0);
            if (op < 0x58) {
                if (s.gpr[4] < 8 || s.gpr[4] - 8 > UINT32_MAX ||
                    mem.check(static_cast<uint32_t>(s.gpr[4] - 8), 8, Write) != MemoryFault::none) {
                    s.exit = CpuExit::memoryFault; break;
                }
                const uint64_t v = s.gpr[reg];
                uint8_t bytes[8]{};
                for (unsigned i = 0; i < 8; ++i) bytes[i] = uint8_t(v >> (8 * i));
                if (mem.write(static_cast<uint32_t>(s.gpr[4] - 8), bytes) != MemoryFault::none) {
                    s.exit = CpuExit::memoryFault; break;
                }
                s.gpr[4] -= 8;
            } else {
                if (s.gpr[4] > UINT32_MAX) { s.exit = CpuExit::memoryFault; break; }
                uint8_t bytes[8]{};
                if (mem.read(static_cast<uint32_t>(s.gpr[4]), bytes) != MemoryFault::none) {
                    s.exit = CpuExit::memoryFault; break;
                }
                uint64_t v = 0;
                for (unsigned i = 0; i < 8; ++i) v |= uint64_t(bytes[i]) << (8 * i);
                s.gpr[4] += 8;
                s.gpr[reg] = v;
            }
            s.rip = pc;
            continue;
        }
        if (op == 0x31 || op == 0x89 || op == 0x8b || op == 0x01 || op == 0x29 || op == 0x39) {
            uint8_t modrm{};
            if (!read(pc++, modrm)) { s.exit = CpuExit::memoryFault; break; }
            const unsigned src = ((modrm >> 3) & 7) + ((rex & 4) ? 8 : 0);
            const unsigned dst = (modrm & 7) + ((rex & 1) ? 8 : 0);
            const uint64_t mask = wide ? UINT64_MAX : UINT32_MAX;
            // Register-indirect MOV, with guest permissions checked on every access.
            // Complex SIB, RIP-relative and displacement addressing remain unsupported.
            if ((modrm & 0xc0) == 0x00 && (modrm & 7) != 4 &&
                (modrm & 7) != 5 && (op == 0x89 || op == 0x8b)) {
                const uint64_t address = s.gpr[dst];
                const unsigned width = wide ? 8u : 4u;
                if (address > UINT32_MAX) { s.exit = CpuExit::memoryFault; break; }
                uint8_t data[8]{};
                if (op == 0x89) {
                    for (unsigned i = 0; i < width; ++i)
                        data[i] = uint8_t(s.gpr[src] >> (8 * i));
                    if (mem.write(static_cast<uint32_t>(address),
                                  std::span<const uint8_t>(data, width)) != MemoryFault::none) {
                        s.exit = CpuExit::memoryFault; break;
                    }
                } else {
                    if (mem.read(static_cast<uint32_t>(address),
                                 std::span<uint8_t>(data, width)) != MemoryFault::none) {
                        s.exit = CpuExit::memoryFault; break;
                    }
                    uint64_t value = 0;
                    for (unsigned i = 0; i < width; ++i)
                        value |= uint64_t(data[i]) << (8 * i);
                    s.gpr[src] = value;
                }
                s.rip = pc;
                continue;
            }
            if ((modrm & 0xc0) != 0xc0) { s.exit = CpuExit::unsupported; break; }
            const uint64_t a = s.gpr[dst] & mask, b = s.gpr[src] & mask;
            if (op == 0x31) { s.gpr[dst] = (a ^ b) & mask; s.zf = s.gpr[dst] == 0; }
            if (op == 0x89) s.gpr[dst] = b;
            if (op == 0x8b) s.gpr[src] = a;
            if (op == 0x01) { s.gpr[dst] = (a + b) & mask; s.zf = s.gpr[dst] == 0; }
            if (op == 0x29) { s.gpr[dst] = (a - b) & mask; s.zf = s.gpr[dst] == 0; }
            if (op == 0x39) s.zf = a == b;
            s.rip = pc;
            continue;
        }
        if (op == 0xeb || op == 0x74 || op == 0x75) {
            uint8_t disp{};
            if (!read(pc++, disp)) { s.exit = CpuExit::memoryFault; break; }
            if (op == 0xeb || (op == 0x74 ? s.zf : !s.zf)) {
                const int64_t dest = static_cast<int64_t>(pc) + static_cast<int8_t>(disp);
                if (dest < 0 || uint64_t(dest) > UINT32_MAX ||
                    mem.check(static_cast<uint32_t>(dest), 1, Execute) != MemoryFault::none) {
                    s.exit = CpuExit::memoryFault; break;
                }
                pc = static_cast<uint64_t>(dest);
            }
            s.rip = pc;
            continue;
        }
        s.exit = CpuExit::unsupported;
        break;
    }
    return s;
}
} // namespace genesis
