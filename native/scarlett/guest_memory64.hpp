#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <functional>
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

    static constexpr uint64_t DirectHeapBase =
        0x800000000ULL;

    static constexpr uint64_t DirectHeapLimit =
        0x1000000000ULL;

    bool enableDirectHeap() {
        if (sysconf(_SC_PAGESIZE) != PageSize)
            return false;
        directHeapEnabled = true;
        return true;
    }

    static constexpr uint64_t DirectVirtualBase =
        0x1000000000ULL;

    static constexpr uint64_t DirectVirtualLimit =
        0x2000000000ULL;

    bool enableDirectVirtual() {
        if(sysconf(_SC_PAGESIZE)!=PageSize ||
           !reservations.empty())
            return false;

        directVirtualEnabled=true;
        return true;
    }

    size_t nativeReservationCount() const {
        return nativeReservations.size();
    }

    ~GuestMemory64() {
        for(const auto& [a,n]:nativeReservations)
            munmap(reinterpret_cast<void*>(a),n);

        for (const auto& [a,n] : directHeapMappings)
            munmap(reinterpret_cast<void*>(a),n);
    }

    size_t directHeapCount() const {
        return directHeapMappings.size();
    }

    uint64_t codeGeneration() const { return codeEpoch; }

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



    using ExternalCheck = std::function<
        Fault(uint64_t,uint64_t,uint8_t)>;

    using ExternalRead = std::function<
        Fault(uint64_t,std::span<uint8_t>)>;

    using ExternalWrite = std::function<
        Fault(uint64_t,std::span<const uint8_t>)>;

    using ExternalContains = std::function<
        bool(uint64_t)>;

    void bindExternalMemory(
        ExternalContains contains,
        ExternalCheck check,
        ExternalRead read,
        ExternalWrite write) {

        externalContains = std::move(contains);
        externalCheck = std::move(check);
        externalRead = std::move(read);
        externalWrite = std::move(write);
    }

private:
    ExternalContains externalContains;
    ExternalCheck externalCheck;
    ExternalRead externalRead;
    ExternalWrite externalWrite;

public:

    // V80 reservation engine
private:
    std::map<uint64_t,uint64_t> reservations;

    // V80 commitment budget
    static constexpr uint64_t CommitPageLimit =
        (512ULL<<20)/PageSize;

    uint64_t reservationCommitted=0;


    bool overlapsReservation(uint64_t a,uint64_t n) const {
        auto it=reservations.lower_bound(a);
        if(it!=reservations.end() && it->first<a+n)
            return true;
        if(it!=reservations.begin()){
            --it;
            if(it->first+it->second>a)return true;
        }
        return false;
    }

public:
    bool reservedRange(uint64_t a,uint64_t n) const {
        if(!n || n>UINT64_MAX-a)return false;
        auto it=reservations.upper_bound(a);
        if(it==reservations.begin())return false;
        --it;
        return a>=it->first &&
               a+n<=it->first+it->second;
    }

    Fault reserve(uint64_t a,uint64_t n){
        if(!n || a%PageSize || n%PageSize ||
           n>UINT64_MAX-a || n>(64ULL<<30))
            return Fault::overflow;

        if(reservations.size()>=4096 ||
           overlapsReservation(a,n) ||
           overlapsSparse(a,n))
            return Fault::permission;

        for(const auto& entry:pages)
            if(entry.first>=a/PageSize &&
               entry.first<(a+n)/PageSize)
                return Fault::permission;

        if(directVirtualEnabled){
            if(a<DirectVirtualBase ||
               a>=DirectVirtualLimit ||
               n>DirectVirtualLimit-a)
                return Fault::permission;

            void* target=reinterpret_cast<void*>(a);
            void* result=mmap(
                target,n,PROT_NONE,
                MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

            if(result==MAP_FAILED)
                return Fault::overflow;

            if(result!=target){
                munmap(result,n);
                return Fault::permission;
            }

            try {
                nativeReservations.emplace(a,n);
                reservations.emplace(a,n);
            } catch(...) {
                nativeReservations.erase(a);
                reservations.erase(a);
                munmap(result,n);
                return Fault::overflow;
            }

            return Fault::none;
        }

        reservations.emplace(a,n);
        return Fault::none;
    }

    Fault commit(uint64_t a,uint64_t n,uint8_t perm){
        if(!n || a%PageSize || n%PageSize ||
           n/PageSize>65536 || (perm&~7u))
            return Fault::overflow;

        if(!reservedRange(a,n))
            return Fault::unmapped;


        uint64_t needed=0;
        for(uint64_t i=0;i<n;i+=PageSize)
            if(!pages.contains((a+i)/PageSize))
                ++needed;

        if(reservationCommitted>CommitPageLimit ||
           needed>CommitPageLimit-reservationCommitted)
            return Fault::overflow;

        // Build new page descriptors first so allocation failure leaves the reservation intact.
        decltype(pages) pending;
        try {
            pending.reserve(needed);
            for(uint64_t i=0;i<n;i+=PageSize){
                const auto number=(a+i)/PageSize;
                if(!pages.contains(number))pending.emplace(number,Page{perm,nullptr});
            }
            pages.reserve(pages.size()+needed);
        } catch(const std::bad_alloc&) {
            return Fault::overflow;
        }
        if(isNativeVirtual(a)){
            for(uint64_t i=0;i<n;i+=PageSize){
                const auto number=(a+i)/PageSize;
                if(!pending.contains(number))
                    continue;

                if(mprotect(
                    reinterpret_cast<void*>(a+i),
                    PageSize,nativeProtection(perm))!=0){

                    for(uint64_t j=0;j<i;j+=PageSize)
                        if(pending.contains((a+j)/PageSize))
                            mprotect(
                                reinterpret_cast<void*>(a+j),
                                PageSize,PROT_NONE);

                    return Fault::permission;
                }
            }
        }

        pages.merge(pending);
        reservationCommitted+=needed;
        if(needed && (perm&Execute))++codeEpoch;
        return Fault::none;
    }

    Fault decommit(uint64_t a,uint64_t n){
        if(!n || a%PageSize || n%PageSize)
            return Fault::overflow;

        if(!reservedRange(a,n))
            return Fault::unmapped;

        if(isNativeVirtual(a)){
            void* ptr=reinterpret_cast<void*>(a);

            if(madvise(ptr,n,MADV_DONTNEED)!=0)
                return Fault::permission;

            if(mprotect(ptr,n,PROT_NONE)!=0)
                return Fault::permission;
        }

        for(auto it=pages.begin();it!=pages.end();){
            if(it->first>=a/PageSize &&
               it->first<(a+n)/PageSize){
                if(it->second.permissions&Execute)
                    ++codeEpoch;

                it=pages.erase(it);
                --reservationCommitted;
            }else ++it;
        }
        return Fault::none;
    }

    Fault releaseReservation(uint64_t a){
        auto it=reservations.find(a);
        if(it==reservations.end())
            return Fault::unmapped;

        auto result=decommit(a,it->second);
        if(result!=Fault::none)return result;

        auto native=nativeReservations.find(a);

        if(native!=nativeReservations.end()){
            if(munmap(reinterpret_cast<void*>(a),
                      native->second)!=0)
                return Fault::permission;

            nativeReservations.erase(native);
        }

        reservations.erase(it);
        return Fault::none;
    }


    uint64_t reservationCommittedPages() const {
        return reservationCommitted;
    }

    size_t reservationCount() const {
        return reservations.size();
    }

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

        if (overlapsReservation(address,length)) return Fault::permission;
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

        if (directHeapEnabled &&
            address>=DirectHeapBase &&
            address<DirectHeapLimit) {

            if(length>DirectHeapLimit-address ||
               permissions!=(Read|Write))
                return Fault::permission;

            void* target=reinterpret_cast<void*>(address);

            void* result=mmap(
                target,length,PROT_READ|PROT_WRITE,
                MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

            if(result==MAP_FAILED)
                return Fault::overflow;

            if(result!=target){
                munmap(result,length);
                return Fault::permission;
            }

            try {
                directHeapMappings.emplace(address,length);

                for(uint64_t i=0;i<count;++i)
                    pages.emplace(
                        first+i,Page{permissions,nullptr});

            } catch(...) {
                for(uint64_t i=0;i<count;++i)
                    pages.erase(first+i);

                directHeapMappings.erase(address);
                munmap(result,length);
                return Fault::overflow;
            }

            return Fault::none;
        }

        if (permissions & Execute) ++codeEpoch;
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
        if (overlapsReservation(address,length)) return Fault::permission;
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

        if(isDirectHeap(address)){
            auto it=directHeapMappings.find(address);

            if(it==directHeapMappings.end() ||
               it->second!=length)
                return Fault::permission;

            if(munmap(reinterpret_cast<void*>(address),
                      length)!=0)
                return Fault::permission;

            for(uint64_t i=0;i<length;i+=PageSize)
                pages.erase((address+i)/PageSize);

            directHeapMappings.erase(it);
            return Fault::none;
        }

        if(overlapsReservation(address,length))
            return Fault::permission;
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
        for(uint64_t i=0;i<length;i+=PageSize) {
            auto it=pages.find((address+i)/PageSize);
            if(it->second.permissions & Execute) ++codeEpoch;
            pages.erase(it);
        }
        return Fault::none;
    }

    Fault check(uint64_t address, uint64_t length,
                uint8_t required) const {
        if (externalContains &&
            externalContains(address))
            return externalCheck(
                address, length, required);

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

    // V80 runtime: ordinary mapped pages only; atomic preflight.
    Fault protect(uint64_t address,uint64_t length,uint8_t permissions,uint8_t& old) {
        if(!length || address%PageSize || length%PageSize ||
           length>UINT64_MAX-address || (permissions&~7u)) return Fault::overflow;
        if(length/PageSize>65536 || overlapsSparse(address,length)) return Fault::permission;
        for(uint64_t i=0;i<length;i+=PageSize)
            if(!pages.contains((address+i)/PageSize)) return Fault::unmapped;
        for(uint64_t i=0;i<length;i+=PageSize)
            if(isDirectHeap(address+i))
                return Fault::permission;

        old=pages.at(address/PageSize).permissions;

        if(isNativeVirtual(address)){
            if(!reservedRange(address,length))
                return Fault::permission;

            if(mprotect(
                reinterpret_cast<void*>(address),
                length,nativeProtection(permissions))!=0)
                return Fault::permission;
        }
        for(uint64_t i=0;i<length;i+=PageSize) {
            auto& page=pages.at((address+i)/PageSize);
            if((page.permissions^permissions)&Execute) ++codeEpoch;
            page.permissions=permissions;
        }
        return Fault::none;
    }

    bool fetchByte(uint64_t address, uint8_t& value) const {
        const auto page = pages.find(address/PageSize);
        if (page == pages.end() || !(page->second.permissions & Execute)) return false;
        if(isNativeVirtual(address)){
            value=*reinterpret_cast<const uint8_t*>(address);
            return true;
        }

        value = page->second.data ? (*page->second.data)[address%PageSize] : 0;
        return true;
    }

    Fault read(uint64_t address,
               std::span<uint8_t> output) const {
        if (externalContains &&
            externalContains(address))
            return externalRead(address, output);

        if(isDirectHeap(address)){
            auto it=directHeapMappings.upper_bound(address);
            --it;

            if(output.size()>it->second-(address-it->first))
                return Fault::unmapped;

            if(!output.empty())
                std::memcpy(output.data(),
                    reinterpret_cast<const void*>(address),
                    output.size());

            return Fault::none;
        }

        if(isNativeVirtual(address)){
            if(output.empty())return Fault::none;

            if(!reservedRange(address,output.size()))
                return Fault::unmapped;

            auto fault=check(address,output.size(),Read);
            if(fault!=Fault::none)return fault;

            std::memcpy(output.data(),
                reinterpret_cast<const void*>(address),
                output.size());

            return Fault::none;
        }

        // V80 J3: ordinary single-page read fast path.
        if(!output.empty() &&
           output.size()<=UINT64_MAX-address &&
           output.size()<=PageSize-address%PageSize){

            auto it=pages.find(address/PageSize);

            if(it!=pages.end()){
                const auto& page=it->second;

                if(!(page.permissions&Read))
                    return Fault::permission;

                if(page.data)
                    std::copy_n(
                        page.data->begin()+address%PageSize,
                        output.size(),output.begin());
                else
                    std::fill(output.begin(),
                              output.end(),uint8_t{0});

                return Fault::none;
            }
        }

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
        if (externalContains &&
            externalContains(address))
            return externalWrite(address, input);

        if(isDirectHeap(address)){
            auto it=directHeapMappings.upper_bound(address);
            --it;

            if(input.size()>it->second-(address-it->first))
                return Fault::unmapped;

            if(!input.empty())
                std::memcpy(
                    reinterpret_cast<void*>(address),
                    input.data(),input.size());

            return Fault::none;
        }

        if(isNativeVirtual(address)){
            if(input.empty())return Fault::none;

            if(!reservedRange(address,input.size()))
                return Fault::unmapped;

            auto fault=check(address,input.size(),Write);
            if(fault!=Fault::none)return fault;

            std::memcpy(
                reinterpret_cast<void*>(address),
                input.data(),input.size());

            for(uint64_t p=address/PageSize;
                p<=(address+input.size()-1)/PageSize;++p)
                if(pages.at(p).permissions&Execute)
                    ++codeEpoch;

            return Fault::none;
        }

        // V80 J3: ordinary single-page write fast path.
        if(!input.empty() &&
           input.size()<=UINT64_MAX-address &&
           input.size()<=PageSize-address%PageSize){

            auto it=pages.find(address/PageSize);

            if(it!=pages.end()){
                auto& page=it->second;

                if(!(page.permissions&Write))
                    return Fault::permission;

                if(!page.data)
                    page.data=std::make_unique<
                        std::array<uint8_t,PageSize>>();

                std::copy(input.begin(),input.end(),
                    page.data->begin()+address%PageSize);

                if(page.permissions&Execute)
                    ++codeEpoch;

                return Fault::none;
            }
        }

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

            if (p.permissions & Execute) ++codeEpoch;
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
        if(isDirectHeap(address) ||
           isNativeVirtual(address))
            return write(address,input);

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

            if (p.permissions & Execute) ++codeEpoch;
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
    bool directHeapEnabled=false;
    bool directVirtualEnabled=false;

    std::map<uint64_t,uint64_t> nativeReservations;

    bool isNativeVirtual(uint64_t a) const {
        auto it=nativeReservations.upper_bound(a);
        if(it==nativeReservations.begin())
            return false;
        --it;
        return a-it->first<it->second;
    }

    static int nativeProtection(uint8_t perm) {
        int prot=PROT_NONE;
        if(perm&(Read|Execute)) prot|=PROT_READ;
        if(perm&Write) prot|=PROT_WRITE;
        return prot;
    }

    std::map<uint64_t,uint64_t> directHeapMappings;

    bool isDirectHeap(uint64_t a) const {
        auto it=directHeapMappings.upper_bound(a);
        if(it==directHeapMappings.begin())
            return false;
        --it;
        return a-it->first<it->second;
    }

    uint64_t codeEpoch=0;
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
