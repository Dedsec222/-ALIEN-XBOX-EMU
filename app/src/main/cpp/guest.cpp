#include "guest.hpp"

namespace genesis {
Result interpret(std::span<const uint8_t> code, size_t budget, size_t entry,
                 uint32_t input, uint32_t target) {
    Result cpu{Stop::budget};
    cpu.ecx = input;
    cpu.rip = entry;
    if (entry > code.size()) {
        cpu.stop = Stop::invalidTarget;
        return cpu;
    }
    bool zero = false;
    while (cpu.steps < budget) {
        const auto bytes = code.subspan(cpu.rip);
        if (bytes.empty()) {
            cpu.stop = Stop::truncated;
            break;
        }
        const uint8_t op = bytes[0];
        size_t length = 1;
        switch (op) {
        case 0xb8:
        case 0xb9: length = 5; break;
        case 0x01:
        case 0xff:
        case 0x31:
        case 0x39:
        case 0x74:
        case 0xeb:
        case 0x75: length = 2; break;
        case 0xcc: break;
        default: cpu.stop = Stop::unsupported; return cpu;
        }
        if (bytes.size() < length) {
            cpu.stop = Stop::truncated;
            break;
        }
        size_t next = cpu.rip + length;
        if (op == 0xb8 || op == 0xb9) {
            uint32_t value = 0;
            for (unsigned i = 0; i < 4; ++i)
                value |= uint32_t(bytes[1 + i]) << (8 * i);
            (op == 0xb8 ? cpu.eax : cpu.ecx) = value;
        } else if (op == 0x01 && bytes[1] == 0xc8) {
            cpu.eax += cpu.ecx;
            zero = cpu.eax == 0;
        } else if (op == 0xff && bytes[1] == 0xc9) {
            zero = --cpu.ecx == 0;
        } else if (op == 0x31 && bytes[1] == 0xc0) {
            cpu.eax = 0;
            zero = true;
        } else if (op == 0x39 && bytes[1] == 0xd1) {
            zero = cpu.ecx == target;
        } else if (op == 0xeb || op == 0x74 || op == 0x75) {
            if (op == 0xeb || (op == 0x74 ? zero : !zero)) {
                int delta = static_cast<int8_t>(bytes[1]);
                if ((delta < 0 && size_t(-delta) > next) ||
                    (delta >= 0 && size_t(delta) >= code.size() - next)) {
                    cpu.stop = Stop::invalidTarget;
                    return cpu;
                }
                next = delta < 0 ? next - size_t(-delta) : next + size_t(delta);
            }
        } else if (op == 0xcc) {
            cpu.stop = Stop::breakpoint;
        } else {
            cpu.stop = Stop::unsupported;
            break;
        }
        cpu.rip = next;
        ++cpu.steps;
        if (cpu.stop == Stop::breakpoint) break;
    }
    return cpu;
}
}
