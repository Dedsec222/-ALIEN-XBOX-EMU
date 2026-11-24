#pragma once
#include "guest_memory64.hpp"
#include <cstdio>

namespace genesis {
struct BlockTrace {
    unsigned depth;
    bool enabled;
    bool opcodes;
    uint64_t first=0,last=0,count=0;
    void flush() {
        if (!count) return;
        std::fprintf(stderr,"BLOCK depth=%u first=%llx last=%llx retired=%llu\n",depth,
                     (unsigned long long)first,(unsigned long long)last,(unsigned long long)count);
        count=0;
    }
    ~BlockTrace(){flush();}
    bool terminator(const GuestMemory64& memory,uint64_t start) const {
        for(unsigned i=0;i<15 && i<=UINT64_MAX-start;++i){
            uint8_t op;
            if (!memory.fetchByte(start+i,op)) return true;
            if ((op>=0x40 && op<=0x4f) || op==0x66 || op==0x67 || op==0x64 || op==0x65 ||
                op==0xf0 || op==0xf2 || op==0xf3 || op==0x26 || op==0x2e || op==0x36 || op==0x3e) continue;
            if (op==0xff || op==0x0f) {
                uint8_t ext;
                if(start+i==UINT64_MAX || !memory.fetchByte(start+i+1,ext))return true;
                if(op==0xff)return (ext&0x38)>=0x10 && (ext&0x38)<=0x28;
                return ext>=0x80 && ext<=0x8f;
            }
            return (op>=0x70 && op<=0x7f) || (op>=0xe0 && op<=0xe3) ||
                   op==0xe8 || op==0xe9 || op==0xeb || op==0xc2 || op==0xc3 || op==0xcc || op==0xf4;
        }
        return true;
    }
    struct Instruction {
        BlockTrace& trace;
        uint64_t rip,before;
        const uint64_t& after;
        bool ends;
        std::array<uint8_t,15> bytes;
        unsigned length=0;
        Instruction(BlockTrace& owner,uint64_t pc,const uint64_t& steps,const GuestMemory64& memory):
            trace(owner),rip(pc),before(steps),after(steps),ends(owner.enabled && owner.terminator(memory,pc)) {
            if(owner.opcodes)while(length<bytes.size() && pc<=UINT64_MAX-length &&
                                  memory.fetchByte(pc+length,bytes[length])) ++length;
        }
        ~Instruction(){
            if(trace.opcodes && before!=after) {
                char hex[31]{};
                constexpr char digits[]="0123456789abcdef";
                for(unsigned i=0;i<length;++i){hex[2*i]=digits[bytes[i]>>4];hex[2*i+1]=digits[bytes[i]&15];}
                std::fprintf(stderr,"RETIRED bytes=%s\n",hex);
            }
            if (!trace.enabled || before==after) return;
            if (!trace.count)trace.first=rip;
            trace.last=rip;
            ++trace.count;
            if (ends)trace.flush();
        }
    };
};
}
