#include "direct_guest_memory.hpp"
#include <cstdio>
#include <cstdint>

#define CHECK(expr) do { \
    if (!(expr)) { \
        std::printf("FAIL: %s\n", #expr); \
        return 1; \
    } \
    std::printf("PASS: %s\n", #expr); \
} while (0)

int main() {
    using Memory = alien::DirectGuestMemory;

    Memory memory;

    constexpr uint64_t base = 0x140000000ULL;
    const size_t page = Memory::pageSize();
    const size_t size = page * 4;

    CHECK(memory.reserve(base, size));

    CHECK(!memory.reserve(base, size));

    CHECK(memory.commit(base, page,
        Memory::Read | Memory::Write));

    auto* value = reinterpret_cast<uint64_t*>(base);

    *value = 0x123456789ABCDEF0ULL;

    CHECK(*value == 0x123456789ABCDEF0ULL);

    CHECK(memory.protect(base, page, Memory::Read));

    CHECK(*value == 0x123456789ABCDEF0ULL);

    CHECK(!memory.commit(base + size, page,
        Memory::Read | Memory::Write));

    CHECK(memory.decommit(base, page));

    CHECK(memory.commit(base, page,
        Memory::Read | Memory::Write));

    CHECK(*value == 0);

    CHECK(memory.release(base));

    CHECK(!memory.contains(base, page));

    CHECK(memory.reserve(base, size));

    CHECK(memory.release(base));

    std::puts("ALL DIRECT MEMORY TESTS PASSED");
    return 0;
}
