#pragma once
#include "guest_memory64.hpp"
#include <array>
#include <cstdint>
#include <limits>

namespace genesis {
enum class Cpu64Exit { breakpoint, halt, unsupported, memoryFault, budget };
struct Cpu64State {
    std::array<uint64_t,16> gpr{};
    uint64_t rip=0, steps=0;
    Cpu64Exit exit=Cpu64Exit::budget;
};
// Deliberately bounded initial execution subset. Not a Scarlett runtime.
inline Cpu64State executeGuest64(GuestMemory64& memory, uint64_t entry,
                                uint64_t budget=100000, uint64_t stackTop=0) {
    Cpu64State s{};
    s.rip=entry;
    s.gpr[4]=stackTop;
    auto fetch=[&](uint64_t& pc, uint8_t& b)->bool {
        if (pc==UINT64_MAX || memory.check(pc,1,GuestMemory64::Execute)!=GuestMemory64::Fault::none)
            return false;
        // Execute-only pages are legal; GuestMemory64::read requires Read too.
        // Until a dedicated fetch method exists, reject execute-only pages safely.
        if (memory.read(pc,std::span<uint8_t>(&b,1))!=GuestMemory64::Fault::none)
            return false;
        ++pc;
        return true;
    };
    for (;s.steps<budget;) {
        uint64_t pc=s.rip;
        uint8_t op=0,rex=0;
        if (!fetch(pc,op)) {s.exit=Cpu64Exit::memoryFault;break;}
        if (op>=0x40 && op<=0x4f) {
            rex=op;
            if (!fetch(pc,op)) {s.exit=Cpu64Exit::memoryFault;break;}
        }
        if (op==0xcc || op==0xf4) {
            s.rip=pc; ++s.steps;
            s.exit=op==0xcc?Cpu64Exit::breakpoint:Cpu64Exit::halt;
            break;
        }
        if (op==0x90) {s.rip=pc;++s.steps;continue;}
        auto imm32=[&](uint32_t& v)->bool {
            v=0;
            for(unsigned i=0;i<4;++i) {
                uint8_t b=0;
                if(!fetch(pc,b)) return false;
                v|=uint32_t(b)<<(8*i);
            }
            return true;
        };
        if (op==0x83 && (rex&8)) {
            uint8_t modrm=0,imm=0;
            if(!fetch(pc,modrm) || !fetch(pc,imm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            if((modrm&0xc7)!=0xc4 || (((modrm>>3)&7)!=0 &&
                ((modrm>>3)&7)!=5)) {
                s.exit=Cpu64Exit::unsupported;break;
            }
            const auto amount=static_cast<int64_t>(static_cast<int8_t>(imm));
            if(((modrm>>3)&7)==5) s.gpr[4]-=static_cast<uint64_t>(amount);
            else s.gpr[4]+=static_cast<uint64_t>(amount);
            s.rip=pc;++s.steps;continue;
        }
        if(op==0xe8 || op==0xe9) {
            uint32_t disp=0;
            if(!imm32(disp)){s.exit=Cpu64Exit::memoryFault;break;}
            const int64_t delta=static_cast<int32_t>(disp);
            uint64_t dest=0;
            if(delta>=0) {
                if(pc>UINT64_MAX-static_cast<uint64_t>(delta)){
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                dest=pc+static_cast<uint64_t>(delta);
            } else {
                const uint64_t magnitude=uint64_t(-(delta+1))+1;
                if(pc<magnitude){s.exit=Cpu64Exit::memoryFault;break;}
                dest=pc-magnitude;
            }
            if(memory.check(dest,1,GuestMemory64::Execute)!=GuestMemory64::Fault::none){
                s.exit=Cpu64Exit::memoryFault;break;
            }
            if(op==0xe8) {
                if(s.gpr[4]<8){s.exit=Cpu64Exit::memoryFault;break;}
                const uint64_t rsp=s.gpr[4]-8;
                std::array<uint8_t,8> ret{};
                for(unsigned i=0;i<8;++i) ret[i]=uint8_t(pc>>(8*i));
                // GuestMemory64::write is non-const; execution needs mutable memory.
                if(memory.write(rsp,ret)!=GuestMemory64::Fault::none){
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                s.gpr[4]=rsp;
            }
            s.rip=dest;++s.steps;continue;
        }
        if(op==0xc3) {
            std::array<uint8_t,8> ret{};
            if(memory.read(s.gpr[4],ret)!=GuestMemory64::Fault::none){
                s.exit=Cpu64Exit::memoryFault;break;
            }
            uint64_t dest=0;
            for(unsigned i=0;i<8;++i) dest|=uint64_t(ret[i])<<(8*i);
            if(memory.check(dest,1,GuestMemory64::Execute)!=GuestMemory64::Fault::none){
                s.exit=Cpu64Exit::memoryFault;break;
            }
            if(s.gpr[4]>UINT64_MAX-8){s.exit=Cpu64Exit::memoryFault;break;}
            s.gpr[4]+=8;s.rip=dest;++s.steps;continue;
        }
        if (op>=0xb8 && op<=0xbf) {
            unsigned reg=(op-0xb8)+((rex&1)?8:0);
            unsigned width=(rex&8)?8:4;
            uint64_t v=0;
            bool ok=true;
            for(unsigned i=0;i<width;++i) {
                uint8_t b=0;
                if(!fetch(pc,b)){ok=false;break;}
                v|=uint64_t(b)<<(i*8);
            }
            if(!ok){s.exit=Cpu64Exit::memoryFault;break;}
            s.gpr[reg]=v;s.rip=pc;++s.steps;continue;
        }
        if (op==0x01 && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)){s.exit=Cpu64Exit::memoryFault;break;}
            if((modrm&0xc0)!=0xc0){s.exit=Cpu64Exit::unsupported;break;}
            unsigned src=((modrm>>3)&7)+((rex&4)?8:0);
            unsigned dst=(modrm&7)+((rex&1)?8:0);
            s.gpr[dst]+=s.gpr[src];
            s.rip=pc;++s.steps;continue;
        }
        s.exit=Cpu64Exit::unsupported;break;
    }
    return s;
}
} // namespace genesis
