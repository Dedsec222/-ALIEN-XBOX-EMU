#pragma once

#include "guest_memory64.hpp"
#include <array>
#include <cstdint>
#include <vector>

namespace genesis {

struct ScarlettRuntime64 {

    static constexpr uint64_t Teb = 0x710000000000ull;
    static constexpr uint64_t Peb = 0x710000010000ull;
    static constexpr uint64_t Tls = 0x710000020000ull;

    static bool put64(GuestMemory64& memory,
                      uint64_t address,
                      uint64_t value) {

        std::array<uint8_t,8> bytes{};

        for(unsigned i=0;i<8;++i)
            bytes[i]=uint8_t(value>>(i*8));

        return memory.write(address,bytes)
            ==GuestMemory64::Fault::none;
    }


    static constexpr uint64_t TlsData =
        0x710000030000ull;

    static bool readValue(
        GuestMemory64& memory,
        uint64_t address,
        unsigned size,
        uint64_t& value) {

        std::array<uint8_t,8> bytes{};

        if(size > bytes.size())
            return false;

        if(memory.read(address,
            std::span<uint8_t>(bytes.data(),size))
            != GuestMemory64::Fault::none)
            return false;

        value = 0;
        for(unsigned i=0;i<size;++i)
            value |= uint64_t(bytes[i])<<(i*8);

        return true;
    }

    static bool installStaticTls(
        GuestMemory64& memory,
        uint64_t base,
        uint64_t tlsVector=Tls,
        uint64_t tlsData=TlsData,
        uint64_t* allocated=nullptr) {

        if(allocated)*allocated=0;

        uint64_t peoff=0, sig=0, magic=0;
        uint64_t count=0, rva=0, dirsize=0;

        if(!readValue(memory,base+0x3c,4,peoff))
            return false;

        if(peoff > 0x100000)
            return false;

        const uint64_t pe=base+peoff;

        if(!readValue(memory,pe,4,sig)
            || sig!=0x4550)
            return false;

        const uint64_t opt=pe+24;

        if(!readValue(memory,opt,2,magic)
            || magic!=0x20b)
            return false;

        if(!readValue(memory,opt+108,4,count))
            return false;

        if(count<=9)
            return true;

        if(!readValue(memory,opt+184,4,rva)
            || !readValue(memory,opt+188,4,dirsize))
            return false;

        if(!rva)
            return true;

        if(dirsize<40)
            return false;

        const uint64_t dir=base+rva;

        uint64_t start=0,end=0,index=0;
        uint64_t zero=0;

        if(!readValue(memory,dir,8,start)
            || !readValue(memory,dir+8,8,end)
            || !readValue(memory,dir+16,8,index)
            || !readValue(memory,dir+32,4,zero))
            return false;

        if(end<start || !index)
            return false;

        const uint64_t raw=end-start;
        constexpr uint64_t limit=16*1024*1024;

        if(raw>limit || zero>limit-raw)
            return false;

        uint64_t size=raw+zero;

        if(!size)
            size=1;

        const uint64_t mapped=
            (size+4095)&~4095ull;

        constexpr auto rw=
            GuestMemory64::Read |
            GuestMemory64::Write;

        if(memory.map(tlsData,mapped,rw)
            != GuestMemory64::Fault::none)
            return false;

        auto rollback=[&](){
            memory.unmap(tlsData,mapped);
            return false;
        };

        std::vector<uint8_t> data(size,0);

        if(raw && memory.read(start,
            std::span<uint8_t>(data.data(),raw))
            != GuestMemory64::Fault::none)
            return rollback();

        if(memory.write(tlsData,data)
            != GuestMemory64::Fault::none)
            return rollback();

        std::array<uint8_t,4> tlsIndex{};

        if(memory.write(index,tlsIndex)
            != GuestMemory64::Fault::none)
            return rollback();

        if(!put64(memory,tlsVector,tlsData))
            return rollback();

        if(allocated)*allocated=mapped;
        return true;
    }

    bool install(GuestMemory64& memory,
                 uint64_t imageBase,
                 uint64_t stackBase,
                 uint64_t stackSize) const {

        constexpr auto rw =
            GuestMemory64::Read |
            GuestMemory64::Write;

        if(memory.map(Teb,8192,rw)
            !=GuestMemory64::Fault::none)
            return false;

        if(memory.map(Peb,4096,rw)
            !=GuestMemory64::Fault::none)
            return false;

        if(memory.map(Tls,4096,rw)
            !=GuestMemory64::Fault::none)
            return false;

        if(!installStaticTls(memory,imageBase))
            return false;

        return
            put64(memory,Teb+0x08,
                  stackBase+stackSize) &&

            put64(memory,Teb+0x10,
                  stackBase) &&

            put64(memory,Teb+0x30,Teb) &&

            put64(memory,Teb+0x40,1000) &&

            put64(memory,Teb+0x48,1) &&

            put64(memory,Teb+0x58,Tls) &&

            put64(memory,Teb+0x60,Peb) &&

            put64(memory,Peb+0x10,imageBase);
    }
};

}
