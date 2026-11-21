#include "pe.hpp"
#include <algorithm>

namespace genesis {
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
