#include "pe.hpp"
#include <algorithm>

namespace genesis {

PeInfo inspectPe(std::span<const uint8_t> file) {
    PeInfo info{};
    const auto fail = [&](const char* error) { info.error = error; return info; };
    const auto fits = [&](uint64_t offset, uint64_t length) {
        return offset <= file.size() && length <= file.size() - offset;
    };
    const auto u16 = [&](size_t p) -> uint16_t {
        return uint16_t(file[p]) | uint16_t(uint16_t(file[p+1]) << 8);
    };
    const auto u32 = [&](size_t p) -> uint32_t {
        return uint32_t(u16(p)) | (uint32_t(u16(p+2)) << 16);
    };
    if (!fits(0, 64) || u16(0) != 0x5a4d) return fail("Missing MZ header");
    const uint32_t pe = u32(0x3c);
    if (pe < 64 || !fits(pe, 24) || u32(pe) != 0x4550)
        return fail("Invalid PE signature");
    if (u16(pe+4) != 0x8664) return fail("Not an AMD64 PE image");
    info.sections = u16(pe+6);
    const uint16_t optSize = u16(pe+20);
    const uint64_t opt = uint64_t(pe) + 24;
    if (!fits(opt, optSize) || optSize < 112 || u16(opt) != 0x20b)
        return fail("Invalid PE32+ optional header");
    info.entryRva = u32(opt+16);
    info.imageSize = u32(opt+56);
    info.imageBase = uint64_t(u32(opt+24)) |
                     (uint64_t(u32(opt+28)) << 32);
    const uint32_t headerSize = u32(opt+60);
    const uint32_t alignment = u32(opt+32);
    const uint32_t count = u32(opt+108);
    if (!info.sections || info.sections > 96 || !info.imageSize ||
        !alignment || headerSize > info.imageSize || headerSize > file.size())
        return fail("Invalid image dimensions");
    if (count > (uint32_t(optSize) - 112u) / 8u) return fail("Truncated data directories");
    if (count > 1) info.importsRva = u32(opt+112+8);
    if (count > 5) info.relocationsRva = u32(opt+112+5*8);
    const uint64_t table = opt + optSize;
    if (!fits(table, uint64_t(info.sections)*40) ||
        headerSize < table + uint64_t(info.sections)*40)
        return fail("Truncated section table");
    bool executableEntry = false;
    for (uint16_t i = 0; i < info.sections; ++i) {
        const uint64_t s = table + uint64_t(i)*40;
        const uint32_t virtualSize = u32(s+8), rva = u32(s+12);
        const uint32_t rawSize = u32(s+16), raw = u32(s+20);
        const uint32_t flags = u32(s+36);
        const uint64_t mappedSize = std::max<uint64_t>(virtualSize, rawSize);
        if ((rawSize && !fits(raw, rawSize)) ||
            uint64_t(rva)+mappedSize > info.imageSize)
            return fail("Section outside file or image");
        if ((flags & 0x20000000u) && info.entryRva >= rva &&
            uint64_t(info.entryRva) < uint64_t(rva)+mappedSize)
            executableEntry = true;
    }
    if (!executableEntry) return fail("Entry point is not in an executable section");
    return info;
}


MappedPe mapPe(std::span<const uint8_t> file) {
    const PeInfo info = inspectPe(file);
    if (info.error) return {{}, 0, info.error};
    // This is a safe staging limit, not an Xbox executable size limit.
    if (info.imageSize > 64u * 1024u * 1024u)
        return {{}, 0, "Image exceeds 64 MiB staging limit"};
    auto u16 = [&](size_t p) -> uint16_t {
        return uint16_t(file[p]) | (uint16_t(file[p+1]) << 8);
    };
    auto u32 = [&](size_t p) -> uint32_t {
        return uint32_t(u16(p)) | (uint32_t(u16(p+2)) << 16);
    };
    const size_t pe = u32(0x3c), opt = pe + 24;
    // No import resolver, relocation engine or OS service layer exists yet.
    // Reject images requiring those services rather than pretending to run them.
    const uint32_t directories = u32(opt + 108);
    for (uint32_t i = 0; i < directories; ++i) {
        if (u32(opt + 112 + size_t(i) * 8) ||
            u32(opt + 116 + size_t(i) * 8))
            return {{}, 0, "PE data directories are not supported yet"};
    }
    const uint32_t headerSize = u32(opt + 60);
    const size_t table = opt + u16(pe + 20);
    MappedPe result{};
    result.entryRva = info.entryRva;
    result.bytes.resize(info.imageSize, 0);
    std::copy_n(file.begin(), headerSize, result.bytes.begin());
    std::vector<std::pair<uint64_t, uint64_t>> regions;
    regions.emplace_back(0, headerSize);
    for (uint16_t i = 0; i < info.sections; ++i) {
        const size_t s = table + size_t(i) * 40;
        const uint32_t virtualSize = u32(s + 8);
        const uint32_t rva = u32(s + 12);
        const uint32_t rawSize = u32(s + 16);
        const uint32_t raw = u32(s + 20);
        const uint64_t span = std::max<uint64_t>(virtualSize, rawSize);
        if (!span) continue;
        for (const auto& [start, end] : regions) {
            if (uint64_t(rva) < end && start < uint64_t(rva) + span)
                return {{}, 0, "Overlapping PE image sections"};
        }
        regions.emplace_back(rva, uint64_t(rva) + span);
        if (rawSize)
            std::copy_n(file.begin() + raw, rawSize, result.bytes.begin() + rva);
    }
    return result;
}

Image loadPe(std::span<const uint8_t> file) {
    const auto fail = [](const char* message) { return Image{{}, 0, 0, message}; };
    const auto fits = [&](size_t at, size_t n) {
        return at <= file.size() && n <= file.size() - at;
    };
    const auto word = [&](size_t p) -> uint32_t { return file[p] | uint32_t(file[p+1]) << 8; };
    const auto dword = [&](size_t p) { return word(p) | (word(p+2) << 16); };
    if (!fits(0, 64) || word(0) != 0x5a4d) return fail("Expected a PE executable (MZ header).");
    size_t pe = dword(60);
    if (pe < 64 || !fits(pe, 24) || dword(pe) != 0x4550) return fail("Invalid PE header.");
    if (word(pe+4) != 0x8664) return fail("Only AMD64 images are supported.");
    if (!(word(pe+22) & 2) || (word(pe+22) & 0x2000)) return fail("Expected an executable, not a DLL.");
    size_t opt = pe + 24, length = word(pe+20);
    if (length < 112 || !fits(opt, length) || word(opt) != 0x20b) return fail("Invalid PE32+ optional header.");
    uint32_t dirs = dword(opt+108);
    if (dirs > (length-112)/8) return fail("Invalid data directory count.");
    for (uint32_t i=0; i<dirs; ++i) {
        if (dword(opt+112+i*8) || dword(opt+116+i*8))
            return fail("This loader supports freestanding images without data directories.");
    }
    size_t table = opt + length, count = word(pe+6);
    if (count != 1 || !fits(table, 40)) return fail("Expected one executable section.");
    size_t raw = dword(table+20), rawSize = dword(table+16);
    uint32_t rva = dword(table+12), virtualSize = dword(table+8);
    uint32_t headers = dword(opt+60), imageSize = dword(opt+56);
    if (headers < table+40 || raw < headers || rva < headers || !fits(raw, rawSize) ||
        uint64_t(rva)+virtualSize > imageSize) return fail("Invalid section bounds.");
    uint32_t entry = dword(opt+16);
    size_t codeSize = std::min<size_t>(rawSize, virtualSize);
    if (!(dword(table+36) & 0x20000000) || entry < rva || entry-rva >= codeSize)
        return fail("Entry point outside executable bytes.");
    return {file.subspan(raw, codeSize), rva, entry-rva, nullptr};
}
}
