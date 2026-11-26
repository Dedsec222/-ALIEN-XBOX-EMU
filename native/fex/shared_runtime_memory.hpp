#pragma once

#include "scarlett_memory_adapter.hpp"
#include <cstring>
#include <array>

namespace alien {

inline void connectRuntimeMemory(
    genesis::GuestMemory64& memory,
    DirectPeLoader& loader,
    uint64_t stackBase,
    uint64_t stackSize,
    uint64_t tebBase,
    uint64_t tebSize) {

    using Fault = genesis::GuestMemory64::Fault;

    struct Region {
        uint64_t base;
        uint64_t size;
    };

    const std::array<Region,2> regions{{
        {stackBase, stackSize},
        {tebBase, tebSize}
    }};

    auto contains = [regions](uint64_t a) {
        for (const auto& r : regions)
            if (a >= r.base &&
                a - r.base < r.size)
                return true;

        return false;
    };

    auto check = [&loader, regions](
        uint64_t a, uint64_t n,
        uint8_t perm) -> Fault {

        if (!n)
            return Fault::none;

        if (n > UINT64_MAX - a)
            return Fault::overflow;

        if (perm & ~7u)
            return Fault::permission;

        for (const auto& r : regions) {
            if (a >= r.base &&
                a - r.base < r.size) {

                if (n > r.size - (a-r.base))
                    return Fault::unmapped;

                if (perm & 4)
                    return Fault::permission;

                return Fault::none;
            }
        }

        if (a < loader.base() ||
            a-loader.base() >= loader.size() ||
            n > loader.size()-(a-loader.base()))
            return Fault::unmapped;

        if (!perm)
            return Fault::none;

        return loader.allowed(a,n,perm)
            ? Fault::none : Fault::permission;
    };

    memory.bindExternalMemory(
        [&loader, contains](uint64_t a) {
            return contains(a) ||
                (a >= loader.base() &&
                 a-loader.base() < loader.size());
        },

        check,

        [check](uint64_t a,
                std::span<uint8_t> out) -> Fault {

            auto result = check(a,out.size(),1);

            if (result == Fault::none &&
                !out.empty())
                std::memcpy(
                    out.data(),
                    reinterpret_cast<const void*>(a),
                    out.size());

            return result;
        },

        [check](uint64_t a,
                std::span<const uint8_t> in) -> Fault {

            auto result = check(a,in.size(),2);

            if (result == Fault::none &&
                !in.empty())
                std::memcpy(
                    reinterpret_cast<void*>(a),
                    in.data(),in.size());

            return result;
        }
    );
}

}
