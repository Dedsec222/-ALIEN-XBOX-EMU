#pragma once
#include "guest_memory64.hpp"
#include <cstring>
#if defined(__aarch64__) && defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace genesis {
// Experimental block compiler. Only register-immediate MOV, BSWAP and NOP
// are eligible. Guest memory and control transfers stay in the interpreter.
class Arm64Blocks {
public:
    uint64_t calls=0,translations=0;
#if defined(__aarch64__) && defined(__linux__)
private:
    struct Block {
        std::array<uint8_t,96> source{};
        unsigned bytes=0,ops=0;
        void* code=nullptr;
        size_t pageSize=0;
        ~Block(){if(code)munmap(code,pageSize);}
    };
    std::unordered_map<uint64_t,std::unique_ptr<Block>> cache;
    bool denied=false;
    static std::unique_ptr<Block> compile(const GuestMemory64& mem,uint64_t start,bool& denied) {
        auto block=std::make_unique<Block>();
        // Up to six words per instruction, plus BTI C and RET.
        std::array<uint32_t,98> words{};
        size_t used=0;
        words[used++]=0xd503245f;
        unsigned offset=0;
        auto fetch=[&](uint8_t& b) {
            if (offset>=block->source.size() || start>=UINT64_MAX-offset ||
                !mem.fetchByte(start+offset,b))return false;
            block->source[offset++]=b;
            return true;
        };
        while(block->ops<16){
            uint8_t op,rex=0;
            if(!fetch(op))break;
            if (op>=0x40 && op<=0x4f){rex=op;if(!fetch(op))break;}
            const bool wide=(rex&8)!=0;
            if(op>=0xb8 && op<=0xbf){
                const unsigned r=(op&7)+((rex&1)?8:0);
                uint64_t value=0;
                bool ok=true;
                for(unsigned i=0;i<(wide?8u:4u);++i){
                    uint8_t b;
                    if(!fetch(b)){ok=false;break;}
                    value|=uint64_t(b)<<(i*8);
                }
                if(!ok)break;
                // MOVZ/MOVK x9, followed by STR x9,[x0,#guestReg*8].
                words[used++]=0xd2800009|(uint32_t(value&65535)<<5);
                for(unsigned part=1;part<(wide?4u:2u);++part){
                    uint32_t half=(value>>(16*part))&65535;
                    if(half)words[used++]=0xf2800009|(part<<21)|(half<<5);
                }
                words[used++]=0xf9000009|(r<<10);
            } else if(op==0x0f) {
                uint8_t ext;
                if(!fetch(ext) || ext<0xc8 || ext>0xcf)break;
                const unsigned r=(ext&7)+((rex&1)?8:0);
                words[used++]=0xf9400009|(r<<10);
                words[used++]=wide?0xdac00d29:0x5ac00929; // REV X9,X9 or REV W9,W9
                words[used++]=0xf9000009|(r<<10);
            } else if(op!=0x90 || (rex&1))break;
            ++block->ops;
            block->bytes=offset;
        }
        if(!block->ops)return {};
        words[used++]=0xd65f03c0;
        const long page=sysconf(_SC_PAGESIZE);
        if(page<=0 || size_t(page)<used*sizeof(uint32_t))return {};
        block->pageSize=size_t(page);
        void* pagePtr=mmap(nullptr,block->pageSize,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(pagePtr==MAP_FAILED){denied=true;return {};}
        block->code=pagePtr;
        std::memcpy(pagePtr,words.data(),used*sizeof(uint32_t));
        __builtin___clear_cache(static_cast<char*>(pagePtr),static_cast<char*>(pagePtr)+used*sizeof(uint32_t));
        if(mprotect(pagePtr,block->pageSize,PROT_READ|PROT_EXEC)!=0){denied=true;return {};}
        return block;
    }
public:
    bool run(const GuestMemory64& mem,uint64_t& rip,std::array<uint64_t,16>& regs,
             uint64_t& steps,uint64_t budget,uint64_t stop) {
        if(denied)return false;
        auto it=cache.find(rip);
        if(it!=cache.end()){
            const Block& old=*it->second;
            for(unsigned i=0;i<old.bytes;++i) {
                uint8_t b;
                if(!mem.fetchByte(rip+i,b) || b!=old.source[i]){
                    cache.erase(it);it=cache.end();break;
                }
            }
        }
        if(it==cache.end()){
            if(cache.size()>=64)return false;
            auto block=compile(mem,rip,denied);
            if(!block)return false;
            it=cache.emplace(rip,std::move(block)).first;
            ++translations;
        }
        const auto& block=*it->second;
        if (block.ops>budget-steps || (stop>=rip && stop-rip<block.bytes))return false;
        using Entry=void(*)(uint64_t*);
        reinterpret_cast<Entry>(block.code)(regs.data());
        rip+=block.bytes;
        steps+=block.ops;
        ++calls;
        return true;
    }
#else
    bool run(const GuestMemory64&,uint64_t&,std::array<uint64_t,16>&,uint64_t&,uint64_t,uint64_t){return false;}
#endif
};
}
