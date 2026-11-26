#pragma once
#include "pe.hpp"
#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>

namespace genesis {
// A bounded guest address space. Host pointers are never exposed to guest code.
enum Permission : uint8_t { Read = 1, Write = 2, Execute = 4 };
enum class MemoryFault { none, unmapped, permission, overflow };
class GuestMemory {
public:
    static constexpr uint32_t pageSize = 4096;
    static constexpr uint32_t maxSize = 64 * 1024 * 1024;
    explicit GuestMemory(uint32_t size) {
        if (size && size <= maxSize && size % pageSize == 0) {
            bytes_.resize(size);
            perms_.resize(size / pageSize);
        }
    }
    uint32_t size() const { return static_cast<uint32_t>(bytes_.size()); }
    MemoryFault protect(uint32_t address, uint32_t length, uint8_t flags) {
        if (flags & ~uint8_t(Read | Write | Execute)) return MemoryFault::permission;
        if (!length || address % pageSize || length % pageSize ||
            !fits(address, length)) return MemoryFault::overflow;
        for (uint64_t p = address / pageSize; p < (uint64_t(address) + length) / pageSize; ++p)
            perms_[p] = flags;
        return MemoryFault::none;
    }
    MemoryFault read(uint32_t address, std::span<uint8_t> out, uint8_t required = Read) const {
        auto fault = check(address, out.size(), required);
        if (fault == MemoryFault::none)
            std::copy_n(bytes_.begin() + address, out.size(), out.begin());
        return fault;
    }
    MemoryFault write(uint32_t address, std::span<const uint8_t> data) {
        auto fault = check(address, data.size(), Write);
        if (fault == MemoryFault::none)
            std::copy(data.begin(), data.end(), bytes_.begin() + address);
        return fault;
    }
    // Host-only loader copy: bypasses guest write permissions after bounds validation.
    MemoryFault initialize(uint32_t address, std::span<const uint8_t> data) {
        if (!fits(address, data.size())) return MemoryFault::overflow;
        std::copy(data.begin(), data.end(), bytes_.begin() + address);
        return MemoryFault::none;
    }
    MemoryFault fetch(uint32_t address, std::span<uint8_t> out) const {
        return read(address, out, Execute);
    }
    MemoryFault load32(uint32_t address, uint32_t& value) const {
        uint8_t data[4]{};
        auto fault = read(address, data);
        if (fault == MemoryFault::none) {
            value = uint32_t(data[0]) | (uint32_t(data[1]) << 8) |
                    (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
        }
        return fault;
    }
    MemoryFault store32(uint32_t address, uint32_t value) {
        const uint8_t data[4] = {uint8_t(value), uint8_t(value >> 8),
                                 uint8_t(value >> 16), uint8_t(value >> 24)};
        return write(address, data);
    }
    MemoryFault check(uint32_t address, size_t length, uint8_t required) const {
        if (!fits(address, length)) return MemoryFault::overflow;
        if (length == 0) return MemoryFault::none;
        const uint64_t first = address / pageSize;
        const uint64_t last = (uint64_t(address) + length - 1) / pageSize;
        for (uint64_t p = first; p <= last; ++p) {
            if (perms_[p] == 0) return MemoryFault::unmapped;
            if ((perms_[p] & required) != required) return MemoryFault::permission;
        }
        return MemoryFault::none;
    }
private:
    bool fits(uint32_t address, size_t length) const {
        return uint64_t(address) <= bytes_.size() &&
               uint64_t(length) <= bytes_.size() - address;
    }
    std::vector<uint8_t> bytes_;
    std::vector<uint8_t> perms_;
};
struct GuestProcess {
    GuestMemory memory;
    uint32_t entry = 0;
    uint32_t stackTop = 0;
    const char* error = nullptr;
    explicit GuestProcess(uint32_t size) : memory(size) {}
};
// Creates distinct executable and writable regions, plus an isolated guest stack.
// No imports, relocation processing, guest syscalls or kernel calls are implied.
inline GuestProcess prepareProcess(std::span<const uint8_t> file) {
    auto mapped = mapPe(file);
    GuestProcess process(GuestMemory::maxSize);
    if (mapped.error) { process.error = mapped.error; return process; }
    const uint32_t pages = (uint32_t(mapped.bytes.size()) + 4095u) / 4096u;
    if (pages >= GuestMemory::maxSize / GuestMemory::pageSize - 16u) {
        process.error = "Guest image leaves no room for stack"; return process;
    }
    if (process.memory.initialize(0, mapped.bytes) != MemoryFault::none) {
        process.error = "Unable to initialize guest image"; return process;
    }
    // Image pages are read-only by default; PE section flags narrow permissions.
    const uint32_t headerPages = (uint32_t(file[0x3c]) | uint32_t(file[0x3d]) << 8 |
        uint32_t(file[0x3e]) << 16 | uint32_t(file[0x3f]) << 24);
    const uint32_t opt = headerPages + 24;
    const auto u16 = [&](size_t p) -> uint16_t {
        return uint16_t(file[p]) | uint16_t(file[p+1]) << 8;
    };
    const auto u32 = [&](size_t p) -> uint32_t {
        return uint32_t(u16(p)) | uint32_t(u16(p+2)) << 16;
    };
    const uint32_t headers = u32(opt + 60);
    const uint32_t headerEnd = (headers + 4095u) / 4096u * 4096u;
    if (process.memory.protect(0, headerEnd, Read) != MemoryFault::none) {
        process.error = "Invalid guest headers"; return process;
    }
    const size_t table = size_t(opt) + u16(headerPages + 20);
    const uint16_t count = u16(headerPages + 6);
    std::vector<uint8_t> pageFlags(process.memory.size() / 4096u, 0);
    for (uint32_t i = 0; i < headerEnd / 4096u; ++i) pageFlags[i] = Read;
    for (uint16_t i = 0; i < count; ++i) {
        const size_t s = table + size_t(i) * 40;
        const uint32_t rva = u32(s + 12);
        const uint32_t length = std::max(u32(s + 8), u32(s + 16));
        const uint32_t flags = u32(s + 36);
        uint8_t perms = 0;
        if (flags & 0x40000000u) perms |= Read;
        if (flags & 0x80000000u) perms |= Write;
        if (flags & 0x20000000u) perms |= Execute;
        if (!perms && length) { process.error = "Section has no access flags"; return process; }
        if (!length) continue;
        const uint32_t first = rva / 4096u;
        const uint32_t last = uint32_t((uint64_t(rva) + length - 1) / 4096u);
        for (uint32_t p = first; p <= last; ++p) {
            if (pageFlags[p] && pageFlags[p] != perms) {
                process.error = "Sections share a page with conflicting permissions"; return process;
            }
            pageFlags[p] = perms;
        }
    }
    for (uint32_t p = 0; p < pageFlags.size(); ++p) {
        if (pageFlags[p] &&
            process.memory.protect(p * 4096u, 4096u, pageFlags[p]) != MemoryFault::none) {
            process.error = "Unable to protect guest section"; return process;
        }
    }
    process.stackTop = process.memory.size();
    if (process.memory.protect(process.stackTop - 16u * 4096u, 16u * 4096u,
                               Read | Write) != MemoryFault::none) {
        process.error = "Unable to allocate guest stack"; return process;
    }
    process.entry = mapped.entryRva;
    if (process.memory.check(process.entry, 1, Execute) != MemoryFault::none)
        process.error = "Guest entry is not executable";
    return process;
}
} // namespace genesis
