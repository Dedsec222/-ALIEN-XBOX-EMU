#pragma once

#include "guest_memory64.hpp"
#include "scarlett_imports64.hpp"
#include <iostream>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <span>
#include <string>
#include <vector>

namespace genesis {

struct ScarlettPeResult {
    uint64_t imageBase = 0;
    uint64_t entry = 0;
    uint32_t imageSize = 0;
    uint16_t sections = 0;
    uint32_t exceptionRva=0,exceptionSize=0;
    std::string error;
};

inline ScarlettPeResult loadScarlettPe(
    std::span<const uint8_t> file,
    GuestMemory64& memory) {

    ScarlettPeResult result{};

    auto fail = [&](const char* message) {
        result.error = message;
        return result;
    };

    auto fits = [&](uint64_t pos, uint64_t len) {
        return pos <= file.size() &&
               len <= file.size() - pos;
    };

    auto u16 = [&](uint64_t p) -> uint16_t {
        return uint16_t(file[p]) |
               (uint16_t(file[p + 1]) << 8);
    };

    auto u32 = [&](uint64_t p) -> uint32_t {
        return uint32_t(u16(p)) |
               (uint32_t(u16(p + 2)) << 16);
    };

    auto u64 = [&](uint64_t p) -> uint64_t {
        return uint64_t(u32(p)) |
               (uint64_t(u32(p + 4)) << 32);
    };

    if (!fits(0, 64) || u16(0) != 0x5A4D)
        return fail("Invalid DOS header");

    const uint64_t pe = u32(0x3C);

    if (!fits(pe, 24) || u32(pe) != 0x4550)
        return fail("Invalid PE signature");

    if (u16(pe + 4) != 0x8664)
        return fail("Not an x86-64 executable");

    const uint16_t count = u16(pe + 6);
    const uint16_t optionalSize = u16(pe + 20);
    const uint64_t opt = pe + 24;

    if (!count || count > 96 ||
        optionalSize < 112 ||
        !fits(opt, optionalSize) ||
        u16(opt) != 0x20B)
        return fail("Invalid PE32+ header");

    const uint64_t base = u64(opt + 24);
    const uint32_t imageSize = u32(opt + 56);
    const uint32_t headerSize = u32(opt + 60);
    const uint32_t entryRva = u32(opt + 16);
    const uint32_t alignment = u32(opt + 32);

    if (!base || !imageSize ||
        imageSize > 512u * 1024u * 1024u ||
        alignment != 4096 ||
        headerSize > imageSize ||
        !fits(0, headerSize) ||
        entryRva >= imageSize ||
        base > UINT64_MAX - imageSize)
        return fail("Invalid image dimensions");

    const uint64_t table = opt + optionalSize;

    if (!fits(table, uint64_t(count) * 40) ||
        table + uint64_t(count) * 40 > headerSize)
        return fail("Invalid section table");

    struct Section {
        uint32_t rva;
        uint32_t raw;
        uint32_t rawSize;
        uint64_t span;
    };

    std::vector<Section> sections;
    std::map<uint64_t, uint8_t> permissions;

    auto addPages = [&](uint64_t start,
                        uint64_t length,
                        uint8_t flags) {
        if (!length) return;
        const uint64_t first = start / 4096;
        const uint64_t last = (start + length - 1) / 4096;

        for (uint64_t p = first; p <= last; ++p)
            permissions[p] |= flags;
    };

    addPages(base, headerSize, GuestMemory64::Read);

    bool executableEntry = false;

    for (uint16_t i = 0; i < count; ++i) {
        const uint64_t s = table + uint64_t(i) * 40;

        const uint32_t virtualSize = u32(s + 8);
        const uint32_t rva = u32(s + 12);
        const uint32_t rawSize = u32(s + 16);
        const uint32_t raw = u32(s + 20);
        const uint32_t flags = u32(s + 36);

        const uint64_t span =
            std::max<uint64_t>(virtualSize, rawSize);

        if (uint64_t(rva) + span > imageSize ||
            (rawSize && !fits(raw, rawSize)))
            return fail("Section outside image or file");

        uint8_t access = 0;

        if (flags & 0x40000000u)
            access |= GuestMemory64::Read;

        if (flags & 0x80000000u)
            access |= GuestMemory64::Write;

        if (flags & 0x20000000u)
            access |= GuestMemory64::Execute;

        // Metadata-only PE sections may have no R/W/X flags.
        // Keep them readable without granting write or execute.
        if (span && !access)
            access = GuestMemory64::Read;

        if ((access & GuestMemory64::Execute) &&
            entryRva >= rva &&
            uint64_t(entryRva) < uint64_t(rva) + span)
            executableEntry = true;

        addPages(base + rva, span, access);

        sections.push_back({rva, raw, rawSize, span});
    }

    if (!executableEntry)
        return fail("Entry point is not executable");

    // Reject overlapping section byte ranges.
    for (size_t i = 0; i < sections.size(); ++i) {
        if (!sections[i].span) continue;

        for (size_t j = i + 1; j < sections.size(); ++j) {
            if (!sections[j].span) continue;

            const uint64_t a = sections[i].rva;
            const uint64_t b = sections[j].rva;

            if (a < b + sections[j].span &&
                b < a + sections[i].span)
                return fail("Overlapping PE sections");
        }
    }

    // Combine consecutive pages with identical permissions.
    auto it = permissions.begin();

    while (it != permissions.end()) {
        const uint64_t first = it->first;
        const uint8_t flags = it->second;
        uint64_t end = first + 1;
        ++it;

        while (it != permissions.end() &&
               it->first == end &&
               it->second == flags) {
            ++end;
            ++it;
        }

        const auto fault = memory.map(
            first * 4096,
            (end - first) * 4096,
            flags);

        if (fault != GuestMemory64::Fault::none)
            return fail("Guest page mapping failed");
    }

    if (memory.initialize(
            base,
            file.first(headerSize)) !=
        GuestMemory64::Fault::none)
        return fail("Header initialization failed");

    for (const auto& section : sections) {
        if (!section.rawSize) continue;

        if (memory.initialize(
                base + section.rva,
                file.subspan(section.raw, section.rawSize)) !=
            GuestMemory64::Fault::none)
            return fail("Section initialization failed");
    }

    if(optionalSize>=144 && u32(opt+108)>3){
        result.exceptionRva=u32(opt+136);result.exceptionSize=u32(opt+140);
        if(result.exceptionRva>imageSize || result.exceptionSize>imageSize-result.exceptionRva || result.exceptionSize%12) return fail("Invalid exception directory");
    }
    result.imageBase = base;
    result.entry = base + entryRva;
    result.imageSize = imageSize;
    result.sections = count;

    return result;
}

inline bool resolveScarlettImports(GuestMemory64& mem,
    const ScarlettPeResult& pe, ScarlettImports64& imports) {
    auto read=[&](uint64_t r,unsigned n,uint64_t& val) {
        std::array<uint8_t,8> b{};
        if(r>pe.imageSize || n>pe.imageSize-r ||
           mem.read(pe.imageBase+r,std::span<uint8_t>(b.data(),n))
           !=GuestMemory64::Fault::none) return false;
        val=0; for(unsigned i=0;i<n;++i) val|=uint64_t(b[i])<<(8*i);
        return true;
    };
    auto str=[&](uint64_t r,std::string& out) {
        for(unsigned i=0;i<4096;++i) {
            uint64_t c;
            if(!read(r+i,1,c)) return false;
            if(!c) return true;
            out+=char(c);
        }
        return false;
    };
    uint64_t h,n,dir,size;
    if(!read(0x3c,4,h)||!read(h+20,2,n)||n<112) return false;
    uint64_t count;
    if(!read(h+24+108,4,count)) return false;
    if(count<2) return true;
    if(n<128 || !read(h+24+120,4,dir)||!read(h+24+124,4,size)) return false;
    if(!dir && !size) return true;
    if(!dir || size<20 || dir>pe.imageSize || size>pe.imageSize-dir) return false;
    unsigned resolved=0, missing=0;
    for(uint64_t d=dir;d+20<=dir+size;d+=20) {
        uint64_t oft,dll,iat,time,chain;
        if(!read(d,4,oft)||!read(d+4,4,time)||!read(d+8,4,chain)||
           !read(d+12,4,dll)||!read(d+16,4,iat)) return false;
        if(!(oft|dll|iat|time|chain)) {
            std::cout<<"Imports resolved: "<<std::dec<<resolved<<" missing: "<<missing<<"\n";
            return true;
        }
        std::string library;
        if(!dll || !iat || !str(dll,library)) return false;
        uint64_t table=oft?oft:iat;
        for(uint64_t i=0;;i+=8) {
            uint64_t thunk,old;
            if(!read(table+i,8,thunk)||!read(iat+i,8,old)) return false;
            if(!thunk) break;
            std::string symbol;
            if(thunk>>63) symbol="#"+std::to_string(thunk&65535);
            else if(thunk>UINT32_MAX || !str(thunk+2,symbol)) return false;
            auto addr=imports.registerImport(library,symbol);
            if(!addr) { imports.recordMissing(pe.imageBase+iat+i,library+"!"+symbol); ++missing; std::cout<<"Missing import: "<<library<<"!"<<symbol<<"\n"; continue; }
            std::array<uint8_t,8> b{};
            for(unsigned j=0;j<8;++j) b[j]=uint8_t(addr>>(8*j));
            if(mem.initialize(pe.imageBase+iat+i,b)!=GuestMemory64::Fault::none) return false;
            ++resolved;
        }
    }
    return false;
}

} // namespace genesis
