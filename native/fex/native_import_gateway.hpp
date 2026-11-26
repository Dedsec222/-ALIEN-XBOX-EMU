#pragma once

#include "scarlett_dispatch.hpp"
#include "hle_bridge.hpp"
#include "../core/direct_pe_loader.hpp"

#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#include <optional>
#include <stdexcept>
#include <cstdio>
#include <cstring>

namespace alien {

class NativeImportGateway {
public:
    struct Binding {
        PeImport import;
        uint64_t thunk;
        uint64_t scarlettAddress;
    };

    std::vector<Binding> bindings;

    NativeImportGateway()=default;

    NativeImportGateway(
        const NativeImportGateway&)=delete;

    NativeImportGateway& operator=(
        const NativeImportGateway&)=delete;

    ~NativeImportGateway(){
        if(mapping_)
            munmap(mapping_,size_);
    }

    bool initialize(size_t count){

        if(mapping_ || !count || count>65536)
            return false;

        const long page=sysconf(_SC_PAGESIZE);

        if(page<=0)
            return false;

        const size_t bytes=count*16;

        size_=(bytes+page-1)/page*page;

        void* p=mmap(nullptr,size_,
            PROT_READ|PROT_WRITE,
            MAP_PRIVATE|MAP_ANONYMOUS,-1,0);

        if(p==MAP_FAILED)
            return false;

        mapping_=static_cast<uint8_t*>(p);

        // Every byte traps, including accidental
        // execution between registered thunks.
        memset(mapping_,0xCC,size_);

        capacity_=count;
        bindings.reserve(count);

        return true;
    }

    uint64_t base() const {
        return reinterpret_cast<uint64_t>(mapping_);
    }

    size_t size() const {
        return size_;
    }

    std::optional<uint64_t> bind(
        const PeImport& imp,
        ScarlettDispatch& runtime){

        if(!mapping_ || sealed_ ||
           bindings.size()>=capacity_)
            return std::nullopt;

        const uint64_t address=
            imp.by_ordinal ? 0 :
            runtime.bind(imp.module,imp.symbol);

        const uint64_t thunk=
            base()+bindings.size()*16;

        bindings.push_back({
            imp,thunk,address
        });

        return thunk;
    }

    bool seal(){

        if(!mapping_ || sealed_)
            return false;

        if(mprotect(mapping_,size_,PROT_READ)!=0)
            return false;

        sealed_=true;
        return true;
    }

    size_t registeredCount() const {

        size_t count=0;

        for(const auto& b:bindings)
            if(b.scarlettAddress)
                ++count;

        return count;
    }

    size_t unsupportedCount() const {
        return bindings.size()-registeredCount();
    }

    bool install(
        HLEBridge& bridge,
        ScarlettDispatch& runtime){

        if(!sealed_)
            return false;

        for(const auto& b:bindings){

            const std::string name=
                b.import.module+"!"+
                (b.import.by_ordinal ?
                 "#"+std::to_string(b.import.ordinal):
                 b.import.symbol);

            const uint64_t target=b.scarlettAddress;

            if(!bridge.bind(
                b.thunk,name,
                [&runtime,target,name](Frame& frame)
                    ->uint64_t {

                    if(!target){

                        fprintf(stderr,
                            "UNSUPPORTED IMPORT: %s\n"
                            "Guest trap RIP: 0x%llx\n",
                            name.c_str(),
                            (unsigned long long)
                            frame.State.rip);

                        throw std::runtime_error(
                            "Unsupported import: "+name);
                    }

                    return runtime.invoke(target,frame);
                }))
                return false;
        }

        return true;
    }

private:
    uint8_t* mapping_=nullptr;
    size_t size_=0;
    size_t capacity_=0;
    bool sealed_=false;
};

} // namespace alien
