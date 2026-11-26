#include "direct_pe_loader.hpp"
#include <cstdio>
#include <cstdlib>

#define CHECK(x) do { \
    if (!(x)) { \
        std::printf("FAIL: %s\n", #x); \
        std::exit(1); \
    } \
    std::printf("PASS: %s\n", #x); \
} while (0)

static void put(
    alien::Pe64Image& pe,
    size_t offset,
    uint64_t value,
    size_t length
) {
    for (size_t i = 0; i < length; ++i)
        pe.image.at(offset + i) =
            std::byte((value >> (8 * i)) & 255);
}

static alien::Pe64Image fixture() {
    alien::Pe64Image pe;

    const uint32_t p = static_cast<uint32_t>(
        alien::DirectGuestMemory::pageSize());

    pe.image_base = 0x140000000ULL;
    pe.image_size = p * 4;
    pe.header_size = p;
    pe.entry_rva = p;

    pe.image.resize(pe.image_size);

    pe.sections.push_back({
        ".text", p, p, 0, 0, 0x60000000u
    });

    pe.sections.push_back({
        ".data", p * 2, p, 0, 0, 0xc0000000u
    });

    pe.sections.push_back({
        ".reloc", p * 3, p, 0, 0, 0x40000000u
    });

    put(pe, 0x3c, 0x80, 4);
    put(pe, 0x80, 0x4550, 4);
    put(pe, 0x84, 0x8664, 2);
    put(pe, 0x94, 240, 2);

    constexpr size_t opt = 0x98;

    put(pe, opt, 0x20b, 2);
    put(pe, opt + 108, 16, 4);
    put(pe, opt + 152, p * 3, 4);
    put(pe, opt + 156, 12, 4);

    put(pe, p, 0xc3, 1);

    put(pe, p * 2,
        pe.image_base + p, 8);

    put(pe, p * 3, p * 2, 4);
    put(pe, p * 3 + 4, 12, 4);
    put(pe, p * 3 + 8, 0xa000, 2);
    put(pe, p * 3 + 10, 0, 2);

    pe.imports.push_back({
        "test.dll", "TestFunction",
        0, false, p * 2 + 8
    });

    pe.imports.push_back({
        "test.dll", "Unsupported",
        0, false, p * 2 + 16
    });

    return pe;
}

int main() {
    using Memory = alien::DirectGuestMemory;

    const size_t p = Memory::pageSize();

    constexpr uint64_t preferred = 0x140000000ULL;
    constexpr uint64_t relocated = 0x150000000ULL;

    alien::DirectPeLoader loader;

    loader.load(fixture(), relocated,
        [](const alien::PeImport& imp)
            -> std::optional<uint64_t> {
            if (imp.symbol == "TestFunction")
                return 0x12345678ULL;

            return std::nullopt;
        });

    CHECK(loader.base() == relocated);
    CHECK(loader.entry() == relocated + p);

    uint8_t opcode = 0;

    CHECK(loader.fetchByte(loader.entry(), opcode));
    CHECK(opcode == 0xc3);

    CHECK(!loader.write(loader.entry(), &opcode, 1));

    CHECK(!loader.fetchByte(
        relocated + p * 2, opcode));

    uint64_t value = 0;

    CHECK(loader.read(
        relocated + p * 2, &value, 8));

    CHECK(value == relocated + p);

    CHECK(loader.read(
        relocated + p * 2 + 8, &value, 8));

    CHECK(value == 0x12345678ULL);

    CHECK(loader.read(
        relocated + p * 2 + 16, &value, 8));

    CHECK(value == 0);

    CHECK(loader.imports().resolved == 1);
    CHECK(loader.imports().unresolved.size() == 1);

    value = 0xabcdef;

    CHECK(loader.write(
        relocated + p * 2, &value, 8));

    CHECK(!loader.read(
        relocated + p * 4, &value, 8));

    alien::DirectPeLoader second;

    second.load(fixture());

    CHECK(second.base() == preferred);

    CHECK(second.read(
        preferred + p * 2, &value, 8));

    CHECK(value == preferred + p);

    bool rejected = false;

    try {
        alien::DirectPeLoader collision;
        collision.load(fixture());
    } catch (const std::runtime_error&) {
        rejected = true;
    }

    CHECK(rejected);

    std::puts("ALL DIRECT PE TESTS PASSED");
    return 0;
}
