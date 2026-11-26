#pragma once

#include <sys/mman.h>
#include <unistd.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <map>

namespace alien {

class DirectGuestMemory {
public:
    enum Permission : uint8_t {
        Read = 1,
        Write = 2,
        Execute = 4
    };

    DirectGuestMemory() = default;

    DirectGuestMemory(const DirectGuestMemory&) = delete;
    DirectGuestMemory& operator=(
        const DirectGuestMemory&) = delete;

    ~DirectGuestMemory() {
        for (const auto& [base, size] : regions)
            munmap(reinterpret_cast<void*>(base), size);
    }

    static size_t pageSize() {
        return static_cast<size_t>(
            sysconf(_SC_PAGESIZE));
    }

    bool reserve(uint64_t base, size_t size) {
        if (!aligned(base, size))
            return false;

        void* target = reinterpret_cast<void*>(base);

        void* p = mmap(target, size, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (p == MAP_FAILED)
            return false;

        if (p != target) {
            munmap(p, size);
            return false;
        }

        try {
            regions.emplace(base, size);
        } catch (...) {
            munmap(p, size);
            return false;
        }

        return true;
    }

    bool protect(uint64_t base, size_t size,
                 uint8_t permissions) {
        if (!aligned(base, size) ||
            !contains(base, size) ||
            (permissions & ~7u))
            return false;

        int prot = PROT_NONE;

        if (permissions & Read)
            prot |= PROT_READ;
        if (permissions & Write)
            prot |= PROT_WRITE;

        // Guest x86 execution is not native ARM execution.
        if (permissions & Execute)
            prot |= PROT_READ;

        return mprotect(
            reinterpret_cast<void*>(base),
            size, prot) == 0;
    }

    bool commit(uint64_t base, size_t size,
                uint8_t permissions) {
        return protect(base, size, permissions);
    }

    bool decommit(uint64_t base, size_t size) {
        if (!aligned(base, size) ||
            !contains(base, size))
            return false;

        void* p = reinterpret_cast<void*>(base);

        if (mprotect(p, size, PROT_NONE) != 0)
            return false;

        return madvise(p, size, MADV_DONTNEED) == 0;
    }

    bool release(uint64_t base) {
        auto it = regions.find(base);

        if (it == regions.end())
            return false;

        if (munmap(reinterpret_cast<void*>(base),
                   it->second) != 0)
            return false;

        regions.erase(it);
        return true;
    }

    bool contains(uint64_t base, size_t size) const {
        if (!size || size > UINT64_MAX - base)
            return false;

        auto it = regions.upper_bound(base);

        if (it == regions.begin())
            return false;

        --it;

        uint64_t offset = base - it->first;

        return offset <= it->second &&
               size <= it->second - offset;
    }

private:
    std::map<uint64_t, size_t> regions;

    static bool aligned(uint64_t base, size_t size) {
        const size_t page = pageSize();

        return page && size && base &&
               base % page == 0 &&
               size % page == 0 &&
               size <= UINT64_MAX - base;
    }
};

}
