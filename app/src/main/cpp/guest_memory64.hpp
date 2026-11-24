#pragma once

#include <array>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <map>
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

        if (overlapsSparse(address,length)) return Fault::permission;
        if (count > 65536) return Fault::overflow;
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

    // Emulator-internal lazy RW mapping; not an Xbox API contract.
    Fault mapSparse(uint64_t address, uint64_t length, uint8_t permissions) {
        if (!length || address % PageSize || length % PageSize ||
            length > UINT64_MAX-address || length > (64ULL<<30) ||
            permissions != (Read|Write)) return Fault::overflow;
        if (sparse.size() >= 1024 || overlapsSparse(address,length)) return Fault::permission;
        for (const auto& entry : pages)
            if (entry.first >= address/PageSize && entry.first < (address+length)/PageSize)
                return Fault::permission;
        sparse.emplace(address, length);
        return Fault::none;
    }
    size_t sparseCommittedPages() const { return sparseData.size(); }

    Fault unmap(uint64_t address, uint64_t length) {
        if (!length || address % PageSize || length % PageSize || length > UINT64_MAX-address) return Fault::overflow;
        auto region = sparse.find(address);
        if (region != sparse.end() && region->second == length) {
            for (auto it=sparseData.begin(); it!=sparseData.end();) {
                if (it->first >= address/PageSize && it->first < (address+length)/PageSize)
                    it=sparseData.erase(it);
                else ++it;
            }
            sparse.erase(region);
            return Fault::none;
        }
        if (overlapsSparse(address,length)) return Fault::permission;
        if (check(address,length,0)!=Fault::none) return Fault::unmapped;
        for(uint64_t i=0;i<length;i+=PageSize) pages.erase((address+i)/PageSize);
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

            if (it == pages.end()) {
                auto r=sparse.upper_bound(p*PageSize);
                if (r==sparse.begin()) return Fault::unmapped;
                --r;
                if (p*PageSize-r->first >= r->second) return Fault::unmapped;
                if (required & ~uint8_t(Read|Write)) return Fault::permission;
                const auto end=(r->first+r->second)/PageSize-1;
                if (last<=end) return Fault::none;
                p=end;
                continue;
            }

            if ((it->second.permissions & required) != required)
                return Fault::permission;

            if (p == last)
                break;
        }

        return Fault::none;
    }

    bool fetchByte(uint64_t address, uint8_t& value) const {
        const auto page = pages.find(address/PageSize);
        if (page == pages.end() || !(page->second.permissions & Execute)) return false;
        value = page->second.data ? (*page->second.data)[address%PageSize] : 0;
        return true;
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

            const auto& pool=pages.contains(page)?pages:sparseData;
            auto found=pool.find(page);
            if (found==pool.end()) {
                std::fill_n(output.begin()+i,amount,uint8_t{0});
                i+=amount; continue;
            }
            const auto& p = found->second;

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

        // Preflight sparse backing budget before changing any bytes.
        size_t needed=0;
        if (!input.empty()) for (uint64_t p=address/PageSize; p<=(address+input.size()-1)/PageSize; ++p)
            if (!pages.contains(p) && !sparseData.contains(p)) ++needed;
        if (needed > 32768-sparseData.size()) return Fault::overflow;

        for (size_t i = 0; i < input.size();) {
            const uint64_t current = address + i;
            const uint64_t page = current / PageSize;
            const size_t offset = current % PageSize;
            const size_t amount =
                std::min<size_t>(input.size() - i,
                                 PageSize - offset);

            auto& p = pages.contains(page) ? pages.at(page) :
                sparseData.try_emplace(page,Page{Read|Write,nullptr}).first->second;

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
        return count + sparseData.size();
    }

private:
    struct Page {
        uint8_t permissions;
        std::unique_ptr<
            std::array<uint8_t, PageSize>> data;
    };

    bool overlapsSparse(uint64_t address,uint64_t length) const {
        auto it=sparse.lower_bound(address);
        if (it!=sparse.end() && it->first-address<length) return true;
        if (it!=sparse.begin()) { --it; if(address-it->first<it->second) return true; }
        return false;
    }
    std::map<uint64_t,uint64_t> sparse;
    std::unordered_map<uint64_t, Page> sparseData;
    std::unordered_map<uint64_t, Page> pages;
};

}
