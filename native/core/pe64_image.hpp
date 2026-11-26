
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace alien {

struct PeSection {
    std::string name;

    uint32_t virtual_address{};
    uint32_t virtual_size{};
    uint32_t raw_offset{};
    uint32_t raw_size{};
    uint32_t characteristics{};

    bool readable() const noexcept {
        return (characteristics & 0x40000000u) != 0;
    }

    bool writable() const noexcept {
        return (characteristics & 0x80000000u) != 0;
    }

    bool executable() const noexcept {
        return (characteristics & 0x20000000u) != 0;
    }
};

struct PeImport {
    std::string module;
    std::string symbol;

    uint16_t ordinal{};
    bool by_ordinal{};

    uint32_t iat_rva{};
};

struct ImportReport {
    size_t resolved{};
    std::vector<PeImport> unresolved;
};


struct PeTlsDirectory {
    uint32_t rva{};
    uint32_t size{};
};

struct PeTlsInfo {
    uint64_t template_start{};
    uint64_t template_end{};
    uint64_t index_address{};
    uint64_t callbacks_address{};
    uint32_t zero_fill{};
    uint32_t characteristics{};

    std::vector<std::byte> initial_data;
    std::vector<uint64_t> callbacks;
};

class Pe64Image {
public:
    using Resolver = std::function<
        std::optional<uint64_t>(const PeImport&)
    >;

    uint64_t image_base{};
    uint32_t entry_rva{};
    uint32_t image_size{};
    uint32_t header_size{};

    std::vector<PeSection> sections;
    std::vector<PeImport> imports;
    std::optional<PeTlsDirectory> tls_directory;

    std::vector<std::byte> image;

    static Pe64Image parse(
        std::span<const std::byte> file,
        uint64_t maximum_image_size =
            2ull * 1024 * 1024 * 1024
    ) {
        Pe64Image pe;

        if (read<uint16_t>(file, 0) != 0x5A4D)
            fail("Invalid DOS signature");

        const uint64_t nt =
            read<uint32_t>(file, 0x3C);

        if (read<uint32_t>(file, nt) != 0x4550)
            fail("Invalid PE signature");

        const uint64_t coff = nt + 4;

        if (read<uint16_t>(file, coff) != 0x8664)
            fail("Expected AMD64 image");

        const auto section_count =
            read<uint16_t>(file, coff + 2);

        const auto optional_size =
            read<uint16_t>(file, coff + 16);

        const uint64_t opt = coff + 20;

        requireRange(file, opt, optional_size);

        if (optional_size < 112)
            fail("Truncated optional header");

        if (read<uint16_t>(file, opt) != 0x20B)
            fail("Expected PE32+ optional header");

        pe.entry_rva =
            read<uint32_t>(file, opt + 16);

        pe.image_base =
            read<uint64_t>(file, opt + 24);

        pe.image_size =
            read<uint32_t>(file, opt + 56);

        pe.header_size =
            read<uint32_t>(file, opt + 60);

        if (!pe.image_size ||
            pe.image_size > maximum_image_size)
            fail("Invalid image size");

        if (pe.header_size > pe.image_size)
            fail("Headers exceed image size");

        if (pe.image_base >
            UINT64_MAX - pe.image_size)
            fail("Image address overflow");

        if (pe.entry_rva >= pe.image_size)
            fail("Entry point outside image");

        requireRange(file, 0, pe.header_size);

        const uint64_t section_table =
            opt + optional_size;

        requireRange(
            file,
            section_table,
            uint64_t(section_count) * 40
        );

        pe.image.resize(pe.image_size);

        std::memcpy(
            pe.image.data(),
            file.data(),
            pe.header_size
        );

        for (uint32_t i = 0;
             i < section_count;
             ++i) {

            const uint64_t p =
                section_table + uint64_t(i) * 40;

            PeSection s;

            for (size_t n = 0; n < 8; ++n) {
                char c = static_cast<char>(
                    std::to_integer<uint8_t>(file[p+n])
                );

                if (!c)
                    break;

                s.name.push_back(c);
            }

            s.virtual_size =
                read<uint32_t>(file, p + 8);

            s.virtual_address =
                read<uint32_t>(file, p + 12);

            s.raw_size =
                read<uint32_t>(file, p + 16);

            s.raw_offset =
                read<uint32_t>(file, p + 20);

            s.characteristics =
                read<uint32_t>(file, p + 36);

            const uint64_t mapped_size = std::max(
                s.virtual_size,
                s.raw_size
            );

            requireRange(
                pe.image,
                s.virtual_address,
                mapped_size
            );

            if (mapped_size &&
                s.virtual_address < pe.header_size)
                fail("Section overlaps PE headers");

            for (const auto& old : pe.sections) {
                const uint64_t old_size = std::max(
                    old.virtual_size,
                    old.raw_size
                );

                if (mapped_size && old_size &&
                    uint64_t(s.virtual_address) <
                        uint64_t(old.virtual_address)
                        + old_size &&
                    uint64_t(old.virtual_address) <
                        uint64_t(s.virtual_address)
                        + mapped_size)
                    fail("Overlapping PE sections");
            }

            if (s.raw_size) {
                requireRange(
                    file,
                    s.raw_offset,
                    s.raw_size
                );

                std::memcpy(
                    pe.image.data() + s.virtual_address,
                    file.data() + s.raw_offset,
                    s.raw_size
                );
            }

            pe.sections.push_back(s);
        }

        const uint32_t directory_count =
            read<uint32_t>(file, opt + 108);

        if (directory_count >= 2) {
            if (optional_size < 128)
                fail("Truncated import directory");

            const uint32_t import_rva =
                read<uint32_t>(file, opt + 120);

            const uint32_t import_size =
                read<uint32_t>(file, opt + 124);

            if (import_rva && import_size)
                pe.parseImports(
                    import_rva,
                    import_size
                );
            else if (import_rva || import_size)
                fail("Invalid import directory");
        }

        
        if(directory_count>=10){
            if(optional_size<192)
                fail("Truncated TLS directory");

            const auto rva=
                read<uint32_t>(file,opt+184);

            const auto size=
                read<uint32_t>(file,opt+188);

            if(rva || size){
                if(!rva || size<40)
                    fail("Invalid PE64 TLS directory");

                requireRange(pe.image,rva,size);

                pe.tls_directory=
                    PeTlsDirectory{rva,size};
            }
        }

        return pe;

    }

    
    std::optional<PeTlsInfo> readTls(
        uint64_t mapped_base) const {

        if(!tls_directory)
            return std::nullopt;

        const uint64_t d=tls_directory->rva;

        requireRange(image,d,40);

        PeTlsInfo tls;

        tls.template_start=read<uint64_t>(image,d);
        tls.template_end=read<uint64_t>(image,d+8);
        tls.index_address=read<uint64_t>(image,d+16);
        tls.callbacks_address=read<uint64_t>(image,d+24);
        tls.zero_fill=read<uint32_t>(image,d+32);
        tls.characteristics=read<uint32_t>(image,d+36);

        auto toRva=[&](uint64_t va,uint64_t length){
            if(va<mapped_base)
                fail("TLS address below image");

            const uint64_t rva=va-mapped_base;
            requireRange(image,rva,length);
            return rva;
        };

        if(tls.template_end<tls.template_start)
            fail("Invalid TLS template range");

        const uint64_t length=
            tls.template_end-tls.template_start;

        constexpr uint64_t limit=64ULL<<20;

        if(length>limit ||
           tls.zero_fill>limit-length)
            fail("TLS allocation exceeds safety limit");

        if(tls.template_start || tls.template_end){
            const auto rva=
                toRva(tls.template_start,length);

            tls.initial_data.assign(
                image.begin()+rva,
                image.begin()+rva+length);
        }

        if(!tls.index_address)
            fail("Missing TLS index address");

        toRva(tls.index_address,4);

        if(tls.callbacks_address){
            uint64_t cursor=
                toRva(tls.callbacks_address,8);

            bool terminated=false;

            for(size_t i=0;i<4096;++i){
                const auto callback=
                    read<uint64_t>(image,cursor);

                if(!callback){
                    terminated=true;
                    break;
                }

                const auto rva=toRva(callback,1);

                bool executable=false;

                for(const auto& section:sections){
                    const uint64_t size=std::max(
                        section.virtual_size,
                        section.raw_size);

                    if(section.executable() &&
                       rva>=section.virtual_address &&
                       rva-section.virtual_address<size){
                        executable=true;
                        break;
                    }
                }

                if(!executable)
                    fail("Non-executable TLS callback");

                tls.callbacks.push_back(callback);
                cursor+=8;
            }

            if(!terminated)
                fail("Unterminated TLS callback array");
        }

        return tls;
    }

    ImportReport resolveImports(
        const Resolver& resolver
    ) {
        ImportReport report;

        for (const auto& entry : imports) {
            auto address = resolver(entry);

            if (!address || !*address) {
                report.unresolved.push_back(entry);
                continue;
            }

            write64(
                image,
                entry.iat_rva,
                *address
            );

            ++report.resolved;
        }

        return report;
    }

private:
    [[noreturn]]
    static void fail(const char* message) {
        throw std::runtime_error(message);
    }

    static void requireRange(
        std::span<const std::byte> bytes,
        uint64_t offset,
        uint64_t length
    ) {
        if (offset > bytes.size() ||
            length > bytes.size() - offset)
            fail("PE range outside buffer");
    }

    template<typename T>
    static T read(
        std::span<const std::byte> bytes,
        uint64_t offset
    ) {
        static_assert(std::is_unsigned_v<T>);

        requireRange(bytes, offset, sizeof(T));

        T result{};

        for (size_t i = 0; i < sizeof(T); ++i) {
            result |= static_cast<T>(
                uint64_t(std::to_integer<uint8_t>(
                    bytes[offset + i]
                )) << (i * 8)
            );
        }

        return result;
    }

    static void write64(
        std::span<std::byte> bytes,
        uint64_t offset,
        uint64_t value
    ) {
        requireRange(bytes, offset, 8);

        for (size_t i = 0; i < 8; ++i) {
            bytes[offset + i] =
                static_cast<std::byte>(
                    (value >> (i * 8)) & 0xFF
                );
        }
    }

    std::string readString(uint64_t rva) const {
        requireRange(image, rva, 1);

        std::string result;

        constexpr size_t max_length = 4096;

        while (rva < image.size() &&
               result.size() < max_length) {

            const auto c =
                std::to_integer<uint8_t>(image[rva++]);

            if (!c)
                return result;

            result.push_back(static_cast<char>(c));
        }

        fail("Unterminated PE string");
    }

    void parseImports(
        uint32_t directory_rva,
        uint32_t directory_size
    ) {
        requireRange(
            image,
            directory_rva,
            directory_size
        );

        constexpr uint64_t ordinal_flag =
            0x8000000000000000ull;

        const uint64_t end =
            uint64_t(directory_rva) + directory_size;

        for (uint64_t p = directory_rva;
             p + 20 <= end;
             p += 20) {

            const uint32_t original_thunk =
                read<uint32_t>(image, p);

            const uint32_t timestamp =
                read<uint32_t>(image, p + 4);

            const uint32_t forwarder =
                read<uint32_t>(image, p + 8);

            const uint32_t name_rva =
                read<uint32_t>(image, p + 12);

            const uint32_t first_thunk =
                read<uint32_t>(image, p + 16);

            if (!original_thunk &&
                !timestamp &&
                !forwarder &&
                !name_rva &&
                !first_thunk)
                return;

            if (!name_rva || !first_thunk)
                fail("Invalid import descriptor");

            const std::string module =
                readString(name_rva);

            const uint64_t lookup =
                original_thunk
                    ? original_thunk
                    : first_thunk;

            for (uint64_t i = 0;; ++i) {
                const uint64_t lookup_rva =
                    lookup + i * 8;

                const uint64_t iat_rva =
                    uint64_t(first_thunk) + i * 8;

                const uint64_t value =
                    read<uint64_t>(image, lookup_rva);

                requireRange(image, iat_rva, 8);

                if (!value)
                    break;

                PeImport entry;

                entry.module = module;
                entry.iat_rva =
                    static_cast<uint32_t>(iat_rva);

                if (value & ordinal_flag) {
                    entry.by_ordinal = true;
                    entry.ordinal =
                        static_cast<uint16_t>(value);
                } else {
                    if (value > UINT32_MAX)
                        fail("Invalid import name RVA");

                    // Skip IMAGE_IMPORT_BY_NAME.Hint.
                    entry.symbol = readString(value + 2);
                }

                imports.push_back(std::move(entry));
            }
        }

        fail("Missing import descriptor terminator");
    }
};

} // namespace alien

