#pragma once

#include "pe64_image.hpp"
#include "direct_guest_memory.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <vector>

namespace alien {

class DirectPeLoader {
public:
    using Memory = DirectGuestMemory;

    DirectPeLoader() = default;

    DirectPeLoader(const DirectPeLoader&) = delete;
    DirectPeLoader& operator=(
        const DirectPeLoader&) = delete;

    uint64_t base() const noexcept {
        return base_;
    }

    uint64_t entry() const noexcept {
        return entry_;
    }

    size_t size() const noexcept {
        return image_size_;
    }

    const ImportReport& imports() const noexcept {
        return imports_;
    }

    
    const std::optional<PeTlsInfo>& tls()
        const noexcept {
        return tls_;
    }

    void load(
        Pe64Image pe,
        uint64_t requested_base = 0,
        const Pe64Image::Resolver& resolver = {}
    ) {
        if (base_)
            fail("Image already loaded");

        const uint64_t target = requested_base
            ? requested_base : pe.image_base;

        const size_t page = Memory::pageSize();

        if (!page || page > 65536 ||
            !target || target % page)
            fail("Invalid mapping alignment");

        if (!pe.image_size ||
            pe.image.size() != pe.image_size)
            fail("Invalid virtual image");

        const size_t rounded =
            ((size_t(pe.image_size) + page - 1)
            / page) * page;

        if (rounded > UINT64_MAX - target)
            fail("Image address overflow");

        
        if (target != pe.image_base)
            relocate(pe, target);

        auto tlsInfo=pe.readTls(target);

        // TLS metadata now contains relocated guest VAs.

        

        // Unresolved imports are deliberately zeroed.
        // Never invent successful runtime bindings.
        ImportReport report;

        for (const auto& imp : pe.imports) {
            const auto address = resolver
                ? resolver(imp) : std::nullopt;

            if (address && *address) {
                put64(pe.image, imp.iat_rva,
                      *address);
                ++report.resolved;
            } else {
                put64(pe.image, imp.iat_rva, 0);
                report.unresolved.push_back(imp);
            }
        }

        std::vector<uint8_t> permissions(
            rounded / page, 0);

        auto mark = [&](uint64_t rva,
                        uint64_t length,
                        uint8_t flags) {
            if (!length)
                return;

            if (rva > pe.image_size ||
                length > pe.image_size - rva)
                fail("Invalid section range");

            const size_t first = rva / page;
            const size_t last =
                (rva + length - 1) / page;

            for (size_t i = first; i <= last; ++i)
                permissions[i] |= flags;
        };

        mark(0, pe.header_size, Memory::Read);

        bool executable_entry = false;

        for (const auto& s : pe.sections) {
            uint8_t flags = 0;

            if (s.readable())
                flags |= Memory::Read;

            if (s.writable())
                flags |= Memory::Write;

            if (s.executable())
                flags |= Memory::Execute;

            const uint64_t length =
                std::max(s.virtual_size, s.raw_size);

            mark(s.virtual_address, length, flags);

            if (s.executable() &&
                pe.entry_rva >= s.virtual_address &&
                uint64_t(pe.entry_rva) -
                    s.virtual_address < length)
                executable_entry = true;
        }

        if (!executable_entry)
            fail("Entry is not in executable section");

        if (!memory_.reserve(target, rounded))
            fail("Guest address reservation failed");

        try {
            if (!memory_.commit(
                target, rounded,
                Memory::Read | Memory::Write))
                fail("Image commitment failed");

            std::memcpy(
                reinterpret_cast<void*>(target),
                pe.image.data(),
                pe.image_size);

            // Apply final permissions in contiguous runs.
            size_t first = 0;

            while (first < permissions.size()) {
                size_t last = first + 1;

                while (last < permissions.size() &&
                       permissions[last] ==
                       permissions[first])
                    ++last;

                if (!memory_.protect(
                    target + first * page,
                    (last - first) * page,
                    permissions[first]))
                    fail("Section protection failed");

                first = last;
            }

            
            if(tlsInfo){
                const uint64_t offset=
                    tlsInfo->index_address-target;

                const size_t firstIndexPage=offset/page;
                const size_t lastIndexPage=(offset+3)/page;

                for(size_t i=firstIndexPage;
                    i<=lastIndexPage;++i){

                    if(!(permissions[i]&Memory::Write))
                        fail("TLS index is not writable");
                }
            }

            tls_ = std::move(tlsInfo);

            permissions_ = std::move(permissions);
            imports_ = std::move(report);

            page_size_ = page;
            image_size_ = pe.image_size;
            base_ = target;
            entry_ = target + pe.entry_rva;

        } catch (...) {
            memory_.release(target);
            throw;
        }
    }

    bool allowed(
        uint64_t address,
        size_t length,
        uint8_t required
    ) const noexcept {
        if (!base_ || !length ||
            address < base_ ||
            !required || (required & ~7u))
            return false;

        const uint64_t offset = address - base_;

        if (offset >= image_size_ ||
            length > image_size_ - offset)
            return false;

        const size_t first = offset / page_size_;
        const size_t last =
            (offset + length - 1) / page_size_;

        for (size_t i = first; i <= last; ++i) {
            if ((permissions_[i] & required)
                != required)
                return false;
        }

        return true;
    }

    bool read(
        uint64_t address,
        void* output,
        size_t length
    ) const {
        if (!output ||
            !allowed(address, length, Memory::Read))
            return false;

        std::memcpy(output,
            reinterpret_cast<const void*>(address),
            length);

        return true;
    }

    bool write(
        uint64_t address,
        const void* input,
        size_t length
    ) {
        if (!input ||
            !allowed(address, length, Memory::Write))
            return false;

        std::memcpy(
            reinterpret_cast<void*>(address),
            input, length);

        return true;
    }

    bool fetchByte(
        uint64_t address,
        uint8_t& value
    ) const {
        if (!allowed(address, 1, Memory::Execute))
            return false;

        std::memcpy(&value,
            reinterpret_cast<const void*>(address),
            1);

        return true;
    }

private:
    Memory memory_;

    uint64_t base_ = 0;
    uint64_t entry_ = 0;

    size_t image_size_ = 0;
    size_t page_size_ = 0;

    std::vector<uint8_t> permissions_;
    ImportReport imports_;
    std::optional<PeTlsInfo> tls_;


    [[noreturn]]
    static void fail(const char* message) {
        throw std::runtime_error(message);
    }

    template<class T>
    static T get(
        std::span<const std::byte> bytes,
        uint64_t offset
    ) {
        if (offset > bytes.size() ||
            sizeof(T) > bytes.size() - offset)
            fail("PE field outside image");

        uint64_t result = 0;

        for (size_t i = 0; i < sizeof(T); ++i)
            result |= uint64_t(
                std::to_integer<uint8_t>(
                    bytes[offset + i])) << (i * 8);

        return static_cast<T>(result);
    }

    static void put64(
        std::span<std::byte> bytes,
        uint64_t offset,
        uint64_t value
    ) {
        if (offset > bytes.size() ||
            8 > bytes.size() - offset)
            fail("64-bit write outside image");

        for (size_t i = 0; i < 8; ++i)
            bytes[offset + i] = std::byte(
                (value >> (i * 8)) & 0xff);
    }

    static void relocate(
        Pe64Image& pe,
        uint64_t target
    ) {
        auto& bytes = pe.image;

        const uint64_t nt =
            get<uint32_t>(bytes, 0x3c);

        const uint64_t opt = nt + 24;

        const uint16_t opt_size =
            get<uint16_t>(bytes, nt + 20);

        const uint16_t characteristics =
            get<uint16_t>(bytes, nt + 22);

        if (characteristics & 1)
            fail("PE relocations stripped");

        if (opt_size < 160 ||
            get<uint32_t>(bytes, opt + 108) < 6)
            fail("Relocation directory unavailable");

        const uint32_t rva =
            get<uint32_t>(bytes, opt + 152);

        const uint32_t size =
            get<uint32_t>(bytes, opt + 156);

        if (!rva || !size ||
            rva > bytes.size() ||
            size > bytes.size() - rva)
            fail("Invalid relocation directory");

        const uint64_t delta =
            target - pe.image_base;

        const uint64_t end = uint64_t(rva) + size;

        uint64_t cursor = rva;

        while (cursor < end) {
            if (end - cursor < 8)
                fail("Truncated relocation block");

            const uint32_t page_rva =
                get<uint32_t>(bytes, cursor);

            const uint32_t block_size =
                get<uint32_t>(bytes, cursor + 4);

            if (block_size < 8 ||
                block_size > end - cursor ||
                (block_size & 1))
                fail("Invalid relocation block");

            for (uint64_t p = cursor + 8;
                 p < cursor + block_size; p += 2) {

                const uint16_t item =
                    get<uint16_t>(bytes, p);

                const unsigned type = item >> 12;

                if (type == 0)
                    continue;

                if (type != 10)
                    fail("Unsupported relocation type");

                const uint64_t address =
                    uint64_t(page_rva) +
                    (item & 0xfff);

                if (address < end &&
                    address + 8 > rva)
                    fail("Relocation overlaps directory");

                const uint64_t old =
                    get<uint64_t>(bytes, address);

                put64(bytes, address, old + delta);
            }

            cursor += block_size;
        }
    }
};

} // namespace alien
