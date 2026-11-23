#pragma once

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <unordered_map>

namespace genesis {

class GuestMemory64 {
public:
    static constexpr uint64_t PageSize = 4096;

    enum Permission : uint8_t {
        Read = 1,
        Write = 2,
        Execute = 4
    };

    enum class Fault {
        none,
        unmapped,
        permission,
        overflow
    };

    Fault map(uint64_t address, uint64_t length,
              uint8_t permissions) {
        if (!length || address % PageSize ||
            length % PageSize ||
            permissions == 0 ||
            (permissions & ~uint8_t(7)))
            return Fault::overflow;

        if (address > UINT64_MAX - length)
            return Fault::overflow;

        const uint64_t first = address / PageSize;
        const uint64_t count = length / PageSize;

        // Do not overwrite existing mappings.
        for (uint64_t i = 0; i < count; ++i) {
            if (pages.contains(first + i))
                return Fault::permission;
        }

        // Keep individual mapping operations bounded.
        if (count > 65536)
            return Fault::overflow;

        for (uint64_t i = 0; i < count; ++i) {
            pages.emplace(first + i, Page{permissions, nullptr});
        }

        return Fault::none;
    }

    Fault check(uint64_t address, uint64_t length,
                uint8_t required) const {
        if (length > UINT64_MAX - address)
            return Fault::overflow;

        if (!length)
            return Fault::none;

        const uint64_t first = address / PageSize;
        const uint64_t last =
            (address + length - 1) / PageSize;

        for (uint64_t p = first;; ++p) {
            auto it = pages.find(p);

            if (it == pages.end())
                return Fault::unmapped;

            if ((it->second.permissions & required) != required)
                return Fault::permission;

            if (p == last)
                break;
        }

        return Fault::none;
    }

    Fault read(uint64_t address,
               std::span<uint8_t> output) const {
        auto fault = check(address, output.size(), Read);
        if (fault != Fault::none)
            return fault;

        for (size_t i = 0; i < output.size();) {
            const uint64_t current = address + i;
            const uint64_t page = current / PageSize;
            const size_t offset = current % PageSize;
            const size_t amount =
                std::min<size_t>(output.size() - i,
                                 PageSize - offset);

            const auto& p = pages.at(page);

            if (p.data)
                std::copy_n(p.data->begin() + offset,
                            amount, output.begin() + i);
            else
                std::fill_n(output.begin() + i,
                            amount, uint8_t{0});

            i += amount;
        }

        return Fault::none;
    }

    Fault write(uint64_t address,
                std::span<const uint8_t> input) {
        auto fault = check(address, input.size(), Write);
        if (fault != Fault::none)
            return fault;

        for (size_t i = 0; i < input.size();) {
            const uint64_t current = address + i;
            const uint64_t page = current / PageSize;
            const size_t offset = current % PageSize;
            const size_t amount =
                std::min<size_t>(input.size() - i,
                                 PageSize - offset);

            auto& p = pages.at(page);

            if (!p.data)
                p.data = std::make_unique<
                    std::array<uint8_t, PageSize>>();

            std::copy_n(input.begin() + i, amount,
                        p.data->begin() + offset);

            i += amount;
        }

        return Fault::none;
    }


    // Loader-only initialization: validates mapped pages,
    // then copies bytes without requiring guest write access.
    Fault initialize(uint64_t address,
                     std::span<const uint8_t> input) {
        if (input.size() > UINT64_MAX - address)
            return Fault::overflow;

        if (input.empty())
            return Fault::none;

        const uint64_t first = address / PageSize;
        const uint64_t last =
            (address + input.size() - 1) / PageSize;

        for (uint64_t p = first;; ++p) {
            if (!pages.contains(p))
                return Fault::unmapped;
            if (p == last)
                break;
        }

        for (size_t i = 0; i < input.size();) {
            const uint64_t current = address + i;
            const uint64_t page = current / PageSize;
            const size_t offset = current % PageSize;
            const size_t amount =
                std::min<size_t>(input.size() - i,
                                 PageSize - offset);

            auto& p = pages.at(page);

            if (!p.data)
                p.data = std::make_unique<
                    std::array<uint8_t, PageSize>>();

            std::copy_n(input.begin() + i, amount,
                        p.data->begin() + offset);
            i += amount;
        }

        return Fault::none;
    }

    size_t mappedPages() const {
        return pages.size();
    }

    size_t committedPages() const {
        size_t count = 0;
        for (const auto& [address, page] : pages)
            if (page.data)
                ++count;
        return count;
    }

private:
    struct Page {
        uint8_t permissions;
        std::unique_ptr<
            std::array<uint8_t, PageSize>> data;
    };

    std::unordered_map<uint64_t, Page> pages;
};

}
