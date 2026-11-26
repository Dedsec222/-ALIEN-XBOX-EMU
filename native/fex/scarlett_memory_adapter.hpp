#pragma once

#include "../core/direct_pe_loader.hpp"
#include "../scarlett/guest_memory64.hpp"

namespace alien {

inline void connectPeMemory(
    genesis::GuestMemory64& memory,
    DirectPeLoader& loader) {

    using Fault = genesis::GuestMemory64::Fault;

    memory.bindExternalMemory(
        [&loader](uint64_t address) {
            return address >= loader.base() &&
                address - loader.base() < loader.size();
        },

        [&loader](uint64_t address,
                  uint64_t length,
                  uint8_t required) -> Fault {

            if (!length)
                return Fault::none;

            if (length > UINT64_MAX - address)
                return Fault::overflow;

            if (address < loader.base() ||
                address - loader.base() >= loader.size() ||
                length > loader.size() -
                    (address - loader.base()))
                return Fault::unmapped;

            if (!required)
                return Fault::none;

            return loader.allowed(
                address, length, required)
                ? Fault::none
                : Fault::permission;
        },

        [&loader](uint64_t address,
                  std::span<uint8_t> output) -> Fault {

            if (output.empty())
                return Fault::none;

            return loader.read(
                address, output.data(), output.size())
                ? Fault::none
                : Fault::permission;
        },

        [&loader](uint64_t address,
                  std::span<const uint8_t> input) -> Fault {

            if (input.empty())
                return Fault::none;

            return loader.write(
                address, input.data(), input.size())
                ? Fault::none
                : Fault::permission;
        }
    );
}

}
