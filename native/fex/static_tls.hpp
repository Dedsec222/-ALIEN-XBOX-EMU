#pragma once

#include "../core/direct_pe_loader.hpp"
#include "../scarlett/guest_memory64.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace alien {

class StaticTls {
public:
    using Memory=genesis::GuestMemory64;
    using Fault=Memory::Fault;

    uint64_t block=0;
    uint64_t vectorAddress=0;
    uint64_t allocationSize=0;

    std::vector<uint64_t> callbacks;

    bool initialize(
        DirectPeLoader& loader,
        Memory& memory,
        uint64_t teb,
        uint64_t address=0x1FFF000000ULL) {

        if(block || !loader.tls())
            return false;

        const auto& tls=*loader.tls();

        const uint64_t total=
            tls.initial_data.size()+tls.zero_fill;

        if(total>(64ULL<<20))
            return false;

        const unsigned alignmentCode=
            (tls.characteristics>>20)&15;

        if(alignmentCode==15)
            return false;

        const uint64_t alignment=
            alignmentCode ?
            1ULL<<(alignmentCode-1) : 1;

        const uint64_t dataOffset=
            (4096+alignment-1)&~(alignment-1);

        const uint64_t size=
            (dataOffset+(total?total:1)+4095)
            &~4095ULL;

        if(address%65536)
            return false;

        if(memory.reserve(address,size)
            !=Fault::none)
            return false;

        auto rollback=[&](){
            memory.releaseReservation(address);
            return false;
        };

        if(memory.commit(address,size,3)
            !=Fault::none)
            return rollback();

        const uint64_t data=address+dataOffset;

        if(!tls.initial_data.empty()){
            const auto* bytes=
                reinterpret_cast<const uint8_t*>(
                    tls.initial_data.data());

            if(memory.write(data,
                std::span<const uint8_t>(
                    bytes,tls.initial_data.size()))
                !=Fault::none)
                return rollback();
        }

        // Committed anonymous pages are zero-filled.
        // Module zero occupies static TLS vector slot zero.
        std::array<uint8_t,8> pointer{};
        memcpy(pointer.data(),&data,8);

        if(memory.write(address,pointer)
            !=Fault::none)
            return rollback();

        std::array<uint8_t,4> oldIndex{};
        std::array<uint8_t,8> oldVector{};

        if(!loader.read(tls.index_address,
            oldIndex.data(),4))
            return rollback();

        if(memory.read(teb+0x58,oldVector)
            !=Fault::none)
            return rollback();

        uint64_t previousVector=0;
        memcpy(&previousVector,oldVector.data(),8);

        if(previousVector)
            return rollback();

        const uint32_t index=0;

        if(!loader.write(tls.index_address,
            &index,4))
            return rollback();

        memcpy(pointer.data(),&address,8);

        if(memory.write(teb+0x58,pointer)
            !=Fault::none){

            loader.write(tls.index_address,
                oldIndex.data(),4);

            return rollback();
        }

        vectorAddress=address;
        block=data;
        allocationSize=size;
        callbacks=tls.callbacks;

        return true;
    }

    bool cleanup(Memory& memory,uint64_t teb){

        if(!vectorAddress)
            return false;

        std::array<uint8_t,8> zero{};

        if(memory.write(teb+0x58,zero)
            !=Fault::none)
            return false;

        if(memory.releaseReservation(vectorAddress)
            !=Fault::none)
            return false;

        block=0;
        vectorAddress=0;
        allocationSize=0;
        callbacks.clear();

        return true;
    }
};

} // namespace alien
