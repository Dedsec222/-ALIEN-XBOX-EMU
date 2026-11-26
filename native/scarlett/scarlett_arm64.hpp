#pragma once
#include "guest_memory64.hpp"
#include <cstring>
#include <bit>
#if defined(__aarch64__) && defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace genesis {
// Experimental block compiler. Register MOV, BSWAP, NOT, XCHG, simple LEA and NOP
// are eligible. Guest memory and control transfers stay in the interpreter.
class Arm64Blocks {
public:
    uint64_t calls=0,translations=0,negativeHits=0,compileAttempts=0;
    uint64_t memoryCalls=0;
    uint64_t simdCalls=0;
    uint64_t avxCalls=0;
    uint64_t branchCalls=0;
    uint64_t cacheRecycles=0;
    uint64_t hotHits=0;
    uint64_t negativeRecycles=0;
    using VectorBank=
        std::array<std::array<uint8_t,16>,16>;
#if defined(__aarch64__) && defined(__linux__)
private:
    struct Block {
        std::array<uint8_t,96> source{};
        unsigned bytes=0,ops=0;
        unsigned flagMode=0;
        bool simd=false;
        bool avx=false;
        bool branch=false;
        unsigned branchCondition=16;
        uint64_t branchTarget=0;
        uint64_t branchFallthrough=0;
        unsigned memoryMode=0;
        unsigned memoryReg=0;
        unsigned memoryWidth=0;
        void* code=nullptr;
        size_t pageSize=0;
        ~Block(){if(code)munmap(code,pageSize);}
    };
    std::unordered_map<uint64_t,std::unique_ptr<Block>> cache;
    struct HotEntry {
        uint64_t rip=0;
        Block* block=nullptr;
    };

    std::array<HotEntry,1024> hot{};
    bool denied=false;
    const GuestMemory64* owner=nullptr;
    uint64_t epoch=0;
    std::unordered_map<uint64_t,bool> rejected;
    static std::unique_ptr<Block> compile(const GuestMemory64& mem,uint64_t start,bool& denied) {
        auto block=std::make_unique<Block>();
        // Bounded native emission, including SIB addressing.
        std::array<uint32_t,258> words{};
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

            // J4.2: VEX map 0F native integer SIMD.
            if((op==0xc4 || op==0xc5) && !rex){
                uint8_t a=0,b=0,ext=0,m=0;

                if(!fetch(a))break;

                unsigned r=0,rmHigh=0;

                if(op==0xc4){
                    if(!fetch(b))break;
                    if((a&31)!=1)break;

                    r=(a&0x80)?0:8;
                    rmHigh=(a&0x20)?0:8;
                }else{
                    b=a;
                    r=(a&0x80)?0:8;
                }

                if((b&3)!=1)break;
                if(!fetch(ext)||!fetch(m))break;
                if((m>>6)!=3)break;

                unsigned dst=((m>>3)&7)+r;
                unsigned lhs=(~b>>3)&15;
                unsigned rhs=(m&7)+rmHigh;

                bool wideVec=(b&4)!=0;
                uint32_t neon=0;

                switch(ext){
                    case 0xda: neon=0x6e216c00;break;
                    case 0xde: neon=0x6e216400;break;
                    case 0xea: neon=0x4e616c00;break;
                    case 0xee: neon=0x4e616400;break;
                    case 0xdc: neon=0x6e210c00;break;
                    case 0xdd: neon=0x6e610c00;break;
                    case 0xec: neon=0x4e210c00;break;
                    case 0xed: neon=0x4e610c00;break;
                    case 0xd8: neon=0x6e212c00;break;
                    case 0xd9: neon=0x6e612c00;break;
                    case 0xe8: neon=0x4e212c00;break;
                    case 0xe9: neon=0x4e612c00;break;
                    case 0xe0: neon=0x6e211400;break;
                    case 0xe3: neon=0x6e611400;break;
                    case 0xef: neon=0x6e211c00;break;
                    case 0xdb: neon=0x4e211c00;break;
                    case 0xeb: neon=0x4ea11c00;break;
                    case 0xdf: neon=0x4e601c20;break;

                    case 0xfc: neon=0x4e218400;break;
                    case 0xfd: neon=0x4e618400;break;
                    case 0xfe: neon=0x4ea18400;break;
                    case 0xd4: neon=0x4ee18400;break;

                    case 0xf8: neon=0x6e218400;break;
                    case 0xf9: neon=0x6e618400;break;
                    case 0xfa: neon=0x6ea18400;break;
                    case 0xfb: neon=0x6ee18400;break;

                    case 0x74: neon=0x6e218c00;break;
                    case 0x75: neon=0x6e618c00;break;
                    case 0x76: neon=0x6ea18c00;break;
                    case 0xd5: neon=0x4e619c00;break;

                    default:break;
                }

                if(!neon)break;

                // X2: lower XMM bank.
                // X3: upper YMM bank.
                auto emitLane=[&](unsigned bank){
                    words[used++]=0x3dc00000
                        |(lhs<<10)|(bank<<5);

                    words[used++]=0x3dc00001
                        |(rhs<<10)|(bank<<5);

                    words[used++]=neon;

                    words[used++]=0x3d800000
                        |(dst<<10)|(bank<<5);
                };

                emitLane(2);

                if(wideVec){
                    emitLane(3);
                }else{
                    // VEX.128 clears upper 128 bits.
                    // EOR V0.16B,V0.16B,V0.16B.
                    words[used++]=0x6e201c00;

                    words[used++]=0x3d800060
                        |(dst<<10);
                }

                block->simd=true;
                block->avx=true;

                ++block->ops;
                block->bytes=offset;
                continue;
            }

if(op==0x66 && !rex){
                if(!fetch(op))break;

                if(op>=0x40 && op<=0x4f){
                    rex=op;
                    if(!fetch(op))break;
                }

                if(op!=0x0f)break;

                uint8_t ext,m;
                if(!fetch(ext)||!fetch(m))break;
                if((m>>6)!=3)break;

                unsigned dst=((m>>3)&7)
                    +((rex&4)?8:0);

                unsigned src=(m&7)
                    +((rex&1)?8:0);

                uint32_t neon=0;

                switch(ext){
                    case 0xef: neon=0x6e211c00;break;
                    case 0xdb: neon=0x4e211c00;break;
                    case 0xeb: neon=0x4ea11c00;break;
                    case 0xdf: neon=0x4e601c20;break;

                    case 0xfc: neon=0x4e218400;break;
                    case 0xfd: neon=0x4e618400;break;
                    case 0xfe: neon=0x4ea18400;break;
                    case 0xd4: neon=0x4ee18400;break;

                    case 0xf8: neon=0x6e218400;break;
                    case 0xf9: neon=0x6e618400;break;
                    case 0xfa: neon=0x6ea18400;break;
                    case 0xfb: neon=0x6ee18400;break;

                    case 0x74: neon=0x6e218c00;break;
                    case 0x75: neon=0x6e618c00;break;
                    case 0x76: neon=0x6ea18c00;break;

                    case 0xd5: neon=0x4e619c00;break;
                    default:break;
                }

                if(!neon)break;

                words[used++]=0x3dc00040
                    |(dst<<10);

                words[used++]=0x3dc00041
                    |(src<<10);

                words[used++]=neon;

                words[used++]=0x3d800040
                    |(dst<<10);

                block->simd=true;
                ++block->ops;
                block->bytes=offset;
                continue;
            }

            if(!rex && ((op>=0x70 && op<=0x7f)
                    || op==0xeb || op==0xe9
                    || op==0x0f)){
                unsigned cond=16;
                unsigned width=0;

                if(op>=0x70 && op<=0x7f){
                    cond=op&15;
                    width=1;
                }else if(op==0xeb){
                    width=1;
                }else if(op==0xe9){
                    width=4;
                }else{
                    uint8_t ext;
                    if(!mem.fetchByte(start+offset,ext))
                        break;
                    if(ext>=0x80 && ext<=0x8f){
                        if(!fetch(ext))break;
                        cond=ext&15;
                        width=4;
                    }
                }

                if(width){
                    // Isolate branches for precise faults.
                    if(block->ops)break;

                    uint32_t raw=0;
                    bool valid=true;
                    for(unsigned j=0;j<width;++j){
                        uint8_t b;
                        if(!fetch(b)){
                            valid=false;
                            break;
                        }
                        raw|=uint32_t(b)<<(8*j);
                    }
                    if(!valid)break;

                    int64_t delta=width==1
                        ?int64_t(int8_t(raw))
                        :int64_t(int32_t(raw));

                    uint64_t next=start+offset;

                    if(op==0xe9){
                        if(delta>=0 &&
                           next>UINT64_MAX-uint64_t(delta))
                            break;
                        if(delta<0 &&
                           next<uint64_t(-delta))
                            break;
                    }

                    block->branch=true;
                    block->branchCondition=cond;
                    block->branchTarget=next+uint64_t(delta);
                    block->branchFallthrough=next;
                    block->ops=1;
                    block->bytes=offset;
                    break;
                }
            }

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
            } else if(op==0x89 || op==0x8b ||
                      op==0x87 || op==0xf7 ||
                      op==0x8d) {

                uint8_t modrm;
                if(!fetch(modrm))break;

                unsigned mod=modrm>>6;
                unsigned reg=((modrm>>3)&7)
                    +((rex&4)?8:0);
                unsigned rm=(modrm&7)
                    +((rex&1)?8:0);

                auto load=[&](unsigned guest,unsigned host){
                    words[used++]=0xf9400000
                        |(guest<<10)|host;
                };

                auto store=[&](unsigned guest,unsigned host){
                    words[used++]=0xf9000000
                        |(guest<<10)|host;
                };

                auto narrow=[&](unsigned host){
                    if(!wide)
                        words[used++]=0x2a0003e0
                            |(host<<16)|host;
                };

                if(op==0x8d ||
                   ((op==0x89 || op==0x8b) && mod!=3)){

                    const bool transfer=op!=0x8d;

                    // Memory blocks must be isolated so a
                    // failed transfer can safely fall back.
                    if(transfer && block->ops)break;
                    if(mod==3)break;

                    unsigned base=rm;
                    unsigned index=0;
                    unsigned scale=0;

                    bool hasBase=true;
                    bool hasIndex=false;
                    bool ripRelative=false;

                    if((modrm&7)==4){
                        uint8_t sib;
                        if(!fetch(sib))break;

                        scale=sib>>6;

                        index=((sib>>3)&7)
                            +((rex&2)?8:0);

                        hasIndex=((sib>>3)&7)!=4
                            || (rex&2);

                        base=(sib&7)
                            +((rex&1)?8:0);

                        if(mod==0 && (sib&7)==5)
                            hasBase=false;

                    }else if(mod==0 &&
                             (modrm&7)==5){
                        hasBase=false;
                        ripRelative=true;
                    }

                    uint64_t displacement=0;

                    unsigned dispBytes=
                        mod==1?1:
                        (mod==2 || !hasBase)?4:0;

                    bool valid=true;

                    for(unsigned j=0;j<dispBytes;++j){
                        uint8_t b;
                        if(!fetch(b)){
                            valid=false;
                            break;
                        }
                        displacement|=uint64_t(b)<<(8*j);
                    }

                    if(!valid)break;

                    if(dispBytes==1)
                        displacement=uint64_t(
                            int64_t(int8_t(displacement)));

                    if(dispBytes==4)
                        displacement=uint64_t(
                            int64_t(int32_t(displacement)));

                    if(ripRelative)
                        displacement+=start+offset;

                    auto immediate=[&](unsigned host,
                                       uint64_t value){
                        words[used++]=0xd2800000
                            |(uint32_t(value&65535)<<5)
                            |host;

                        for(unsigned j=1;j<4;++j){
                            uint32_t half=
                                (value>>(16*j))&65535;

                            if(half)
                                words[used++]=0xf2800000
                                    |(j<<21)|(half<<5)
                                    |host;
                        }
                    };

                    if(hasBase)
                        load(base,9);
                    else
                        immediate(9,0);

                    if(hasIndex){
                        load(index,10);

                        // ADD X9,X9,X10,LSL #scale
                        words[used++]=0x8b0a0129
                            |(scale<<10);
                    }

                    if(displacement){
                        immediate(11,displacement);

                        // ADD X9,X9,X11
                        words[used++]=0x8b0b0129;
                    }

                    if(transfer){
                        block->memoryMode=op==0x8b?1:2;
                        block->memoryReg=reg;
                        block->memoryWidth=wide?8:4;

                        // Return the full guest address.
                        // STR X9,[X1]
                        words[used++]=0xf9000029;

                        ++block->ops;
                        block->bytes=offset;
                        break;
                    }

                    narrow(9);
                    store(reg,9);

                }else{
                    if(mod!=3)break;

                    if(op==0x89 || op==0x8b){
                        unsigned src=op==0x89?reg:rm;
                        unsigned dst=op==0x89?rm:reg;

                        load(src,9);
                        narrow(9);
                        store(dst,9);

                    }else if(op==0x87){
                        // Register XCHG.
                        load(reg,9);
                        load(rm,10);
                        narrow(9);
                        narrow(10);
                        store(rm,9);
                        store(reg,10);

                    }else if(op==0xf7){
                        // NOT is group 3 /2.
                        if(((modrm>>3)&7)!=2)
                            break;

                        load(rm,9);

                        // MVN X9,X9 or MVN W9,W9.
                        words[used++]=wide
                            ?0xaa2903e9:0x2a2903e9;

                        store(rm,9);
                    }
                }

            } else if(
                op==0x01 || op==0x03 ||
                op==0x09 || op==0x0b ||
                op==0x21 || op==0x23 ||
                op==0x29 || op==0x2b ||
                op==0x31 || op==0x33 ||
                op==0x39 || op==0x3b ||
                op==0x85){

                uint8_t m;
                if(!fetch(m) || (m>>6)!=3)
                    break;

                unsigned reg=((m>>3)&7)
                    +((rex&4)?8:0);

                unsigned rm=(m&7)
                    +((rex&1)?8:0);

                unsigned dst=(op&2)?reg:rm;
                unsigned src=(op&2)?rm:reg;

                const bool compare=
                    op==0x39 || op==0x3b ||
                    op==0x85;

                unsigned kind=op&0xf8;

                // Load guest operands into X9 and X10.
                words[used++]=0xf9400009|(dst<<10);
                words[used++]=0xf940000a|(src<<10);

                uint32_t instruction=0;

                if(kind==0x00){
                    // ADDS X9,X9,X10.
                    instruction=0xab0a0129;
                    block->flagMode=1;

                }else if(kind==0x28 || kind==0x38){
                    // SUBS X9,X9,X10.
                    instruction=0xeb0a0129;
                    block->flagMode=2;

                }else if(kind==0x20 || op==0x85){
                    // ANDS X9,X9,X10.
                    instruction=0xea0a0129;
                    block->flagMode=3;

                }else if(kind==0x08){
                    // ORR X9,X9,X10.
                    instruction=0xaa0a0129;
                    block->flagMode=3;

                }else if(kind==0x30){
                    // EOR X9,X9,X10.
                    instruction=0xca0a0129;
                    block->flagMode=3;
                }

                if(!wide)instruction&=0x7fffffff;
                words[used++]=instruction;

                if(kind==0x08 || kind==0x30){
                    // TST result,result to produce N/Z.
                    words[used++]=wide
                        ?0xea09013f:0x6a09013f;
                }

                if(!compare)
                    words[used++]=0xf9000009|(dst<<10);

                // X1 points to native flag output.
                // Store arithmetic result for parity.
                words[used++]=0xf9000029;

                // MRS X10,NZCV.
                words[used++]=0xd53b420a;

                // STR X10,[X1,#8].
                words[used++]=0xf900042a;

                // End block at flag-producing instruction.
                ++block->ops;
                block->bytes=offset;
                break;

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
        if(block->branch)return block;
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
    bool run(GuestMemory64& mem,uint64_t& rip,std::array<uint64_t,16>& regs,
             uint64_t& steps,uint64_t budget,uint64_t stop,
             bool& zf,bool& cf,bool& of,
             bool& sf,bool& pf,VectorBank& xmm,VectorBank& ymmHigh) {
        if(denied)return false;
        if(owner!=&mem || epoch!=mem.codeGeneration()) {
            hot.fill(HotEntry{}); cache.clear(); rejected.clear(); owner=&mem; epoch=mem.codeGeneration();
        }
        auto& slot=hot[(rip^(rip>>10))&1023];
        Block* selected=nullptr;

        if(slot.block && slot.rip==rip){
            selected=slot.block;
            ++hotHits;
        }

        if(!selected){
        auto it=cache.find(rip);
        if(it==cache.end()){
            if(rejected.contains(rip)){++negativeHits;return false;}
            if(cache.size()>=4096){
                    hot.fill(HotEntry{});
                    cache.clear();
                    ++cacheRecycles;
                }
            ++compileAttempts;
            auto block=compile(mem,rip,denied);
            if(!block){
                    if(rejected.size()>=65536){
                        rejected.clear();
                        ++negativeRecycles;
                    }
                    rejected.emplace(rip,true);
                    return false;
                }
            it=cache.emplace(rip,std::move(block)).first;
            ++translations;
        }
        selected=it->second.get();
        slot={rip,selected};
        }

        const auto& block=*selected;
        for(unsigned i=0;i<block.bytes;++i){uint8_t b; if(!mem.fetchByte(rip+i,b)||b!=block.source[i]){slot=HotEntry{};
                cache.erase(rip);
                return false;}}
        if (block.ops>budget-steps || (stop>=rip && stop-rip<block.bytes))return false;
        if(block.branch){
            bool taken=false;

            switch(block.branchCondition){
                case 0: taken=of;break;
                case 1: taken=!of;break;
                case 2: taken=cf;break;
                case 3: taken=!cf;break;
                case 4: taken=zf;break;
                case 5: taken=!zf;break;
                case 6: taken=cf||zf;break;
                case 7: taken=!cf&&!zf;break;
                case 8: taken=sf;break;
                case 9: taken=!sf;break;
                case 10:taken=pf;break;
                case 11:taken=!pf;break;
                case 12:taken=sf!=of;break;
                case 13:taken=sf==of;break;
                case 14:taken=zf||(sf!=of);break;
                case 15:taken=!zf&&(sf==of);break;
                default:taken=true;break;
            }

            uint64_t dest=taken
                ?block.branchTarget
                :block.branchFallthrough;

            if(mem.check(dest,1,GuestMemory64::Execute)
                !=GuestMemory64::Fault::none)
                return false;

            rip=dest;
            ++steps;
            ++calls;
            ++branchCalls;
            return true;
        }

        std::array<uint64_t,2> flags{};

        using Entry=void(*)(uint64_t*,uint64_t*,uint8_t*,uint8_t*);

        reinterpret_cast<Entry>(block.code)(
            regs.data(),flags.data(),
            reinterpret_cast<uint8_t*>(xmm.data()),
            reinterpret_cast<uint8_t*>(ymmHigh.data()));

        if(block.simd)++simdCalls;
        if(block.avx)++avxCalls;

        if(block.memoryMode){
            const uint64_t address=flags[0];
            const unsigned width=block.memoryWidth;
            const unsigned reg=block.memoryReg;

            std::array<uint8_t,8> data{};

            if(block.memoryMode==1){
                auto fault=mem.read(
                    address,
                    std::span<uint8_t>(data).first(width));

                if(fault!=GuestMemory64::Fault::none)
                    return false;

                uint64_t value=0;

                for(unsigned j=0;j<width;++j)
                    value|=uint64_t(data[j])<<(j*8);

                regs[reg]=value;

            }else{
                const uint64_t value=regs[reg];

                for(unsigned j=0;j<width;++j)
                    data[j]=uint8_t(value>>(j*8));

                auto fault=mem.write(
                    address,
                    std::span<const uint8_t>(data).first(width));

                if(fault!=GuestMemory64::Fault::none)
                    return false;
            }

            ++memoryCalls;
        }

        if(block.flagMode){
            uint64_t nzcv=flags[1];

            sf=(nzcv>>31)&1;
            zf=(nzcv>>30)&1;

            if(block.flagMode==3){
                cf=false;
                of=false;
            }else{
                cf=(nzcv>>29)&1;

                // ARM carry means no borrow for SUB.
                if(block.flagMode==2)cf=!cf;

                of=(nzcv>>28)&1;
            }

            pf=(std::popcount(
                uint8_t(flags[0]))%2)==0;
        }
        rip+=block.bytes;
        steps+=block.ops;
        ++calls;
        return true;
    }
#else
    bool run(GuestMemory64&,uint64_t&,std::array<uint64_t,16>&,uint64_t&,uint64_t,uint64_t,
             bool&,bool&,bool&,bool&,bool&,VectorBank&,VectorBank&){
        return false;
    }
#endif
};
}
