
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace alien {

enum class MemoryProtection : uint8_t {
    None    = 0,
    Read    = 1,
    Write   = 2,
    Execute = 4
};

constexpr MemoryProtection operator|(
    MemoryProtection a,
    MemoryProtection b
) noexcept {
    return static_cast<MemoryProtection>(
        static_cast<uint8_t>(a) |
        static_cast<uint8_t>(b)
    );
}

enum class Register : size_t {
    RAX, RCX, RDX, RBX,
    RSP, RBP, RSI, RDI,
    R8, R9, R10, R11,
    R12, R13, R14, R15
};

struct CpuState {
    std::array<uint64_t, 16> gpr{};
    uint64_t rip{};
    uint64_t rflags{2};

    uint64_t fs_base{};
    uint64_t gs_base{};

    uint32_t mxcsr{0x1F80};

    // Full 256-bit AVX register storage.
    std::array<std::array<std::byte, 32>, 16> ymm{};

    uint64_t& reg(Register r) noexcept {
        return gpr[static_cast<size_t>(r)];
    }

    const uint64_t& reg(Register r) const noexcept {
        return gpr[static_cast<size_t>(r)];
    }
};

enum class ExitReason {
    InstructionBudget,
    ImportCall,
    Breakpoint,
    MemoryFault,
    IllegalInstruction,
    Halted,
    Unsupported,
    BackendError
};

struct ExecutionResult {
    ExitReason reason{ExitReason::BackendError};

    uint64_t instructions{};
    uint64_t rip{};
    uint64_t fault_address{};
    uint64_t import_address{};

    std::string diagnostic;
};

class GuestMemory {
public:
    virtual ~GuestMemory() = default;

    virtual bool map(
        uint64_t address,
        uint64_t size,
        MemoryProtection protection
    ) = 0;

    virtual bool unmap(
        uint64_t address,
        uint64_t size
    ) = 0;

    virtual bool protect(
        uint64_t address,
        uint64_t size,
        MemoryProtection protection
    ) = 0;

    virtual bool read(
        uint64_t address,
        std::span<std::byte> output
    ) const = 0;

    virtual bool write(
        uint64_t address,
        std::span<const std::byte> input
    ) = 0;
};

class CpuBackend {
public:
    virtual ~CpuBackend() = default;

    virtual const char* name() const noexcept = 0;

    virtual bool initialize(
        GuestMemory& memory
    ) = 0;

    virtual bool setState(
        const CpuState& state
    ) = 0;

    virtual CpuState getState() const = 0;

    virtual ExecutionResult execute(
        uint64_t instruction_budget
    ) = 0;

    virtual void invalidateCode(
        uint64_t address,
        uint64_t size
    ) = 0;

    virtual void reset() = 0;
};

} // namespace alien

