#pragma once
#include "guest_memory64.hpp"
#include "scarlett_blocks.hpp"
#include "scarlett_imports64.hpp"
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <cstdint>
#include <limits>
#include <cstdio>
#include <cstdlib>

namespace genesis {
enum class Cpu64Exit { breakpoint, halt, unsupported, memoryFault, budget };
struct Cpu64State {
    std::array<uint64_t,16> gpr{};
    std::array<std::array<uint8_t,16>,16> xmm{};
    std::array<std::array<uint8_t,16>,16> ymmHigh{};
    uint64_t rip=0, steps=0;
    uint32_t mxcsr=0x1f80;
    bool zf=false, cf=false, of=false, sf=false, pf=false;
    Cpu64Exit exit=Cpu64Exit::budget;
};
// Deliberately bounded initial execution subset. Not a Scarlett runtime.
inline Cpu64State executeGuest64(GuestMemory64& memory, uint64_t entry,
                                uint64_t budget=100000, uint64_t stackTop=0,
                                const ScarlettImports64* imports=nullptr,
                                uint64_t gsBase=0,
                                uint64_t fsBase=0, uint64_t stopRip=0, unsigned depth=0,
                                const Cpu64State* initial=nullptr) {
    Cpu64State s=initial?*initial:Cpu64State{};
    s.steps=0; s.exit=Cpu64Exit::budget;
    s.rip=entry;
    s.gpr[4]=stackTop;
    auto fetch=[&](uint64_t& pc, uint8_t& b)->bool {
        if (pc==UINT64_MAX || !memory.fetchByte(pc,b)) return false;
        ++pc;
        return true;
    };
    BlockTrace blocks{depth,std::getenv("ALIEN_BLOCK_TRACE")!=nullptr};
    const bool traceInstructions = std::getenv("ALIEN_INSN_TRACE") != nullptr;
    for (;s.steps<budget;) {
        if(stopRip && s.rip==stopRip) break;
        BlockTrace::Instruction retired{blocks,s.rip,s.steps,s.steps,blocks.enabled && blocks.terminator(memory,s.rip)};
        if(traceInstructions) std::fprintf(stderr,"INSN depth=%u step=%llu rip=%llx rax=%llx rcx=%llx rdx=%llx zf=%u cf=%u\n",unsigned(depth),(unsigned long long)s.steps,(unsigned long long)s.rip,(unsigned long long)s.gpr[0],(unsigned long long)s.gpr[1],(unsigned long long)s.gpr[2],unsigned(s.zf),unsigned(s.cf));
        uint64_t pc=s.rip;
        uint8_t op=0,rex=0;
        if (!fetch(pc,op)) {s.exit=Cpu64Exit::memoryFault;break;}
        // V72: alignment NOPs decode bytes only, never access the operand.
        {
            uint64_t q=pc; uint8_t b=op; bool ok=true; bool rb=false;
            while(b==0x66 || b==0x67 || b==0x2e || b==0x3e || b==0x26 || b==0x36 || b==0x64 || b==0x65 || (b>=0x40 && b<=0x4f)) {
                rb=(b>=0x40 && b<=0x4f) && (b&1);
                if(q-s.rip>=15 || !fetch(q,b)){ok=false;break;}
            }
            if(ok && b==0x90 && !rb){s.rip=q;++s.steps;continue;}
            if(ok && b==0x0f){
                uint8_t e=0;
                if(q-s.rip<15 && fetch(q,e) && e==0x1f){
                    uint8_t m=0;
                    auto take=[&](uint8_t& x){return q-s.rip<15 && fetch(q,x);};
                    if(!take(m)){s.exit=Cpu64Exit::memoryFault;break;}
                    if(m&0x38){s.exit=Cpu64Exit::unsupported;break;}
                    unsigned mod=m>>6,rm=m&7,base=rm;
                    if(mod!=3 && rm==4){uint8_t sib=0;if(!take(sib)){s.exit=Cpu64Exit::memoryFault;break;}base=sib&7;}
                    unsigned n=mod==1?1:mod==2?4:mod==0&&base==5?4:0;
                    for(unsigned j=0;j<n;++j){uint8_t d=0;if(!take(d)){ok=false;break;}}
                    if(!ok){s.exit=Cpu64Exit::memoryFault;break;}
                    s.rip=q;++s.steps;continue;
                }
            }
        }
        // ALIEN_RUNTIME_V4
        // ALIEN_ATOMIC_V5
        bool locked=false;
        if(op==0xf0) {
            locked=true;
            if(!fetch(pc,op)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }
        }
        uint64_t segmentBase=0;
        bool segmentOverride=false;

        while(op==0x64 || op==0x65) {
            segmentOverride=true;
            segmentBase=op==0x65?gsBase:fsBase;

            if(pc-s.rip>=15 || !fetch(pc,op)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }
        }

        if(s.exit==Cpu64Exit::memoryFault)
            break;

        uint8_t simdPrefix=0;
        if(op==0x66 || op==0xf3 || op==0xf2) {
            simdPrefix=op;
            if(!fetch(pc,op)) {s.exit=Cpu64Exit::memoryFault;break;}
        }
        if (op>=0x40 && op<=0x4f) {
            rex=op;
            if (!fetch(pc,op)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }
        }

        if(locked && (segmentOverride || (simdPrefix && simdPrefix!=0x66) || !(op==0x0f || (op<0x40 && (op&7)<=1) || op==0x80 || op==0x81 || op==0x83 || op==0xfe || op==0xff || op==0x86 || op==0x87 || op==0xf6 || op==0xf7))) {s.exit=Cpu64Exit::unsupported;break;}
        // Segment overrides currently supported
        // for unified MOV memory operations only.
        if(segmentOverride &&
           !(op>=0x88 && op<=0x8b) &&
           op!=0xc6 && op!=0xc7 && op!=0x8d) {
            s.exit=Cpu64Exit::unsupported;
            break;
        }
        if (!simdPrefix && (op==0xcc || op==0xf4)) {
            s.rip=pc; ++s.steps;
            s.exit=op==0xcc?Cpu64Exit::breakpoint:Cpu64Exit::halt;
            break;
        }
        if (!simdPrefix && op==0x90 && !(rex&1)) {s.rip=pc;++s.steps;continue;}
        auto imm32=[&](uint32_t& v)->bool {
            v=0;
            for(unsigned i=0;i<4;++i) {
                uint8_t b=0;
                if(!fetch(pc,b)) return false;
                v|=uint32_t(b)<<(8*i);
            }
            return true;
        };




        // ALIEN_UNIFIED_DECODER_V2
        auto maskFor = [](unsigned n)->uint64_t {
            return n == 8 ? UINT64_MAX :
                ((uint64_t(1) << (n*8))-1);
        };

        auto readReg = [&](unsigned r, unsigned n)->uint64_t {
            if(n==1 && !rex && r>=4 && r<8)
                return (s.gpr[r-4]>>8)&255;
            return s.gpr[r]&maskFor(n);
        };

        auto writeReg = [&](unsigned r, unsigned n, uint64_t v) {
            v &= maskFor(n);
            if(n==1 && !rex && r>=4 && r<8) {
                s.gpr[r-4]=(s.gpr[r-4]&~uint64_t(0xff00))|(v<<8);
            } else if(n==4 || n==8) {
                s.gpr[r]=v;
            } else {
                s.gpr[r]=(s.gpr[r]&~maskFor(n))|v;
            }
        };

        auto readImm = [&](unsigned n,uint64_t& v)->bool {
            v=0;
            for(unsigned i=0;i<n;++i) {
                uint8_t b=0;
                if(!fetch(pc,b)) return false;
                v|=uint64_t(b)<<(i*8);
            }
            return true;
        };

        struct Operand {
            bool reg=false;
            bool relative=false;
            unsigned id=0;
            uint64_t addr=0;
        };

        auto decodeRM = [&](uint8_t m,Operand& o)->bool {
            unsigned mode=m>>6, rm=m&7;
            o.id=rm+((rex&1)?8:0);

            if(mode==3) {
                o.reg=true;
                return true;
            }

            bool disp32=false;

            if(rm==4) {
                uint8_t sib=0;
                if(!fetch(pc,sib)) return false;

                unsigned base=sib&7;
                unsigned index=(sib>>3)&7;

                if(index!=4 || (rex&2))
                    o.addr+=s.gpr[index+((rex&2)?8:0)]<<(sib>>6);

                if(mode==0 && base==5)
                    disp32=true;
                else
                    o.addr+=s.gpr[base+((rex&1)?8:0)];

            } else if(mode==0 && rm==5) {
                o.relative=true;
                disp32=true;
            } else {
                o.addr=s.gpr[o.id];
            }

            if(mode==1) {
                uint8_t d=0;
                if(!fetch(pc,d)) return false;
                o.addr+=uint64_t(int64_t(int8_t(d)));
            } else if(mode==2 || disp32) {
                uint32_t d=0;
                if(!imm32(d)) return false;
                o.addr+=uint64_t(int64_t(int32_t(d)));
            }
            return true;
        };

        auto addressOf = [&](const Operand& o) {
            return o.addr+(o.relative?pc:0)+segmentBase;
        };
        // Packed minima and maxima share lane semantics between SSE and VEX.
        auto minMax = [&](unsigned map, uint8_t ext, unsigned width, int source) {
            const bool extended = map == 2 && ext >= 0x38 && ext <= 0x3f;
            const bool basic = map == 1 && (ext == 0xda || ext == 0xde ||
                                            ext == 0xea || ext == 0xee);
            if (!basic && !extended) return false;
            const unsigned type = ext & 3;
            const unsigned lane = extended ? (type == 0 ? 1 : type == 2 ? 2 : 4)
                                           : (ext >= 0xe0 ? 2 : 1);
            const bool signedLane = extended ? type < 2 : lane == 2;
            const uint32_t bias = signedLane ? uint32_t(1) << (8 * lane - 1) : 0;
            const bool maximum = (ext & 4) != 0;
            uint8_t modrm;
            Operand operand;
            if (!fetch(pc, modrm) || !decodeRM(modrm, operand)) {
                s.exit = Cpu64Exit::memoryFault;
                return true;
            }
            const unsigned dest = ((modrm >> 3) & 7) + ((rex & 4) ? 8 : 0);
            const unsigned left = source < 0 ? dest : unsigned(source);
            std::array<uint8_t,32> rhs{};
            if (operand.reg) {
                std::copy_n(s.xmm[operand.id].begin(),16,rhs.begin());
                if (width == 32) std::copy_n(s.ymmHigh[operand.id].begin(),16,rhs.begin()+16);
            } else {
                const auto addr = addressOf(operand);
                if ((source < 0 && addr % 16) ||
                    memory.read(addr,std::span(rhs).first(width)) != GuestMemory64::Fault::none) {
                    s.exit = Cpu64Exit::memoryFault;
                    return true;
                }
            }
            for (unsigned i=0; i<width; i+=lane) {
                const auto& src = i < 16 ? s.xmm[left] : s.ymmHigh[left];
                auto& dst = i < 16 ? s.xmm[dest] : s.ymmHigh[dest];
                uint32_t a=0,b=0;
                std::memcpy(&a,src.data()+(i%16),lane);
                std::memcpy(&b,rhs.data()+i,lane);
                const auto result = ((a^bias) > (b^bias)) == maximum ? a : b;
                std::memcpy(dst.data()+(i%16),&result,lane);
            }
            if (source >= 0 && width == 16) s.ymmHigh[dest].fill(0);
            s.rip=pc;
            ++s.steps;
            return true;
        };
        if (!locked && op == 0x0f && (simdPrefix == 0 || simdPrefix == 0x66)) {
            const auto saved = pc;
            uint8_t ext;
            if (!fetch(pc,ext)) { s.exit=Cpu64Exit::memoryFault; break; }
            if (ext >= 0xc8 && ext <= 0xcf && (!simdPrefix || (rex&8))) {
                const unsigned reg=(ext&7)+((rex&1)?8:0);
                if (rex&8) s.gpr[reg]=__builtin_bswap64(s.gpr[reg]);
                else s.gpr[reg]=__builtin_bswap32(uint32_t(s.gpr[reg]));
                s.rip=pc;
                ++s.steps;
                continue;
            }
            unsigned map=1;
            if (ext==0x38) {
                map=2;
                if (!fetch(pc,ext)) { s.exit=Cpu64Exit::memoryFault; break; }
                if (ext==0xf0 || ext==0xf1) {
                    uint8_t modrm;
                    Operand operand;
                    if (!fetch(pc,modrm) || !decodeRM(modrm,operand)) {s.exit=Cpu64Exit::memoryFault;break;}
                    if (operand.reg) {s.exit=Cpu64Exit::unsupported;break;}
                    const unsigned reg=((modrm>>3)&7)+((rex&4)?8:0);
                    const unsigned width=(rex&8)?8:simdPrefix?2:4;
                    std::array<uint8_t,8> bytes{};
                    auto view=std::span(bytes).first(width);
                    if (ext==0xf0) {
                        if (memory.read(addressOf(operand),view)!=GuestMemory64::Fault::none) {s.exit=Cpu64Exit::memoryFault;break;}
                        uint64_t value=0;
                        for (auto byte:view) value=(value<<8)|byte;
                        writeReg(reg,width,value);
                    } else {
                        for (unsigned i=0;i<width;++i) view[width-1-i]=uint8_t(s.gpr[reg]>>(8*i));
                        if (memory.write(addressOf(operand),view)!=GuestMemory64::Fault::none) {s.exit=Cpu64Exit::memoryFault;break;}
                    }
                    s.rip=pc;
                    ++s.steps;
                    continue;
                }
            }
            if (simdPrefix==0x66 && minMax(map,ext,16,-1)) {
                if (s.exit==Cpu64Exit::memoryFault) break;
                continue;
            }
            pc=saved;
        }
        // V26: VEX map 0F packed moves and bitwise operations.
        if(op==0xc5 || op==0xc4) {
            if(rex || simdPrefix || locked) {s.exit=Cpu64Exit::unsupported;break;}
            uint8_t a=0,b=0,ext=0,m=0;
            if(!fetch(pc,a)) {s.exit=Cpu64Exit::memoryFault;break;}
            if(op==0xc4) {
                if(!fetch(pc,b)) {s.exit=Cpu64Exit::memoryFault;break;}
                if((a&31)!=1 && (a&31)!=2 && (a&31)!=3) {s.exit=Cpu64Exit::unsupported;break;}
                rex=0x40|((~a>>5)&7);
            } else {b=a; rex=0x40|((~a>>5)&4);}
            if(!fetch(pc,ext)) {s.exit=Cpu64Exit::memoryFault;break;}
            const unsigned src=(~b>>3)&15, pp=b&3, n=(b&4)?32:16;
            // V64: lane-local shuffles, unpacking, immediate blends and permutations.
            const bool map1=op==0xc5||(a&31)==1;
            const bool map3=op==0xc4&&(a&31)==3;
            // V76: AVX2 per-element shifts, packed sign and absolute value.
            const bool map2=op==0xc4&&(a&31)==2;
            if (pp==1 && minMax(map1?1:map2?2:3,ext,n,int(src))) {
                if (s.exit==Cpu64Exit::memoryFault) break;
                continue;
            }
            const bool varShift=map2&&pp==1&&(ext==0x45||ext==0x46||ext==0x47)&&(!(b&128)||ext!=0x46);
            const bool signOp=map2&&pp==1&&ext>=0x08&&ext<=0x0a;
            const bool absOp=map2&&pp==1&&ext>=0x1c&&ext<=0x1e&&src==0;
            if(varShift||signOp||absOp){
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0),w=varShift?((b&128)?8:4):1u<<(ext-(signOp?0x08:0x1c));
                std::array<uint8_t,32> x{},y{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                if(rm.reg){for(unsigned j=0;j<n;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned bits=w*8; uint64_t mask=~uint64_t(0)>>(64-bits), sign=uint64_t(1)<<(bits-1);
                for(unsigned j=0;j<n;j+=w){
                    uint64_t l=0,r=0,z=0;std::memcpy(&l,x.data()+j,w);std::memcpy(&r,y.data()+j,w);
                    if(absOp)z=(r&sign)?0-r:r;
                    else if(signOp)z=(r&sign)?0-l:r?l:0;
                    else if(ext==0x46){if(r>=bits)z=(l&sign)?mask:0;else if(!r)z=l;else z=(l>>r)|((l&sign)?(mask^(mask>>r)):0);}
                    else if(r<bits)z=ext==0x45?l>>r:l<<r;
                    z&=mask;std::memcpy(out.data()+j,&z,w);
                }
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V74: signed greater-than and equality masks, including qwords.
            const bool gt=pp==1&&((map1&&ext>=0x64&&ext<=0x66)||(op==0xc4&&(a&31)==2&&ext==0x37));
            const bool eq64=pp==1&&op==0xc4&&(a&31)==2&&ext==0x29;
            if(gt||eq64){
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0),w=map1?1u<<(ext-0x64):8;
                std::array<uint8_t,32> x{},y{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                if(rm.reg){for(unsigned j=0;j<n;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                uint64_t sign=uint64_t(1)<<(w*8-1);
                for(unsigned j=0;j<n;j+=w){uint64_t l=0,r=0;std::memcpy(&l,x.data()+j,w);std::memcpy(&r,y.data()+j,w);std::memset(out.data()+j,(eq64?l==r:(l^sign)>(r^sign))?255:0,w);}
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V73: scalar floating point to signed integer, masked exceptions.
            if(map1&&n==16&&pp>=2&&(ext==0x2c||ext==0x2d)){
                if(src!=0){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0), w=pp==2?4:8;
                bool wide=op==0xc4&&(b&128);
                std::array<uint8_t,8> bytes{};
                if(rm.reg)std::memcpy(bytes.data(),s.xmm[rm.id].data(),w);
                else if(memory.read(addressOf(rm),std::span<uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                double v;
                if(w==4){float f;std::memcpy(&f,bytes.data(),4);v=f;}else std::memcpy(&v,bytes.data(),8);
                if((s.mxcsr&64)&&std::abs(v)<(w==4?double(std::numeric_limits<float>::min()):std::numeric_limits<double>::min()))v=std::copysign(0.0,v);
                unsigned mode=ext==0x2c?3:(s.mxcsr>>13)&3;
                double r=v;
                if(std::isfinite(v)){
                    if(mode==1)r=std::floor(v);else if(mode==2)r=std::ceil(v);else if(mode==3)r=std::trunc(v);
                    else {double f=std::floor(v),d=v-f;r=d<0.5?f:d>0.5?f+1:std::fmod(f,2.0)==0?f:f+1;}
                }
                double limit=wide?0x1p63:0x1p31;
                bool invalid=!std::isfinite(r)||r< -limit||r>=limit;
                if(invalid){s.mxcsr|=1;if(!(s.mxcsr&128)){s.exit=Cpu64Exit::unsupported;break;}}
                else if(r!=v){s.mxcsr|=32;if(!(s.mxcsr&4096)){s.exit=Cpu64Exit::unsupported;break;}}
                s.gpr[reg]=wide?(invalid?UINT64_C(0x8000000000000000):uint64_t(int64_t(r))):(invalid?UINT64_C(0x80000000):uint64_t(uint32_t(int32_t(r))));
                s.rip=pc;++s.steps;continue;
            }
            // V70: variable vector blends, mask register encoded in imm8.
            if(map3&&pp==1&&!(b&128)&&ext>=0x4a&&ext<=0x4c){
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||!fetch(pc,imm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0), mask=imm>>4, w=ext==0x4a?4:ext==0x4b?8:1;
                std::array<uint8_t,32> x{},y{},z{},out{};
                for(unsigned j=0;j<n;++j){x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];z[j]=j<16?s.xmm[mask][j]:s.ymmHigh[mask][j-16];}
                if(rm.reg){for(unsigned j=0;j<n;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                for(unsigned j=0;j<n;j+=w)std::memcpy(out.data()+j,((z[j+w-1]&128)?y:x).data()+j,w);
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V69: integer interleave and full-width dword permutation.
            const bool unpack69=map1&&pp==1&&((ext>=0x60&&ext<=0x62)||(ext>=0x68&&ext<=0x6a)||ext==0x6c||ext==0x6d);
            const bool perm69=op==0xc4&&(a&31)==2&&pp==1&&n==32&&(ext==0x36||ext==0x16)&&!(b&128);
            if(unpack69||perm69){
                Operand rm;if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                std::array<uint8_t,32> x{},y{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                if(rm.reg){for(unsigned j=0;j<n;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                if(perm69){for(unsigned j=0;j<32;j+=4){unsigned k=x[j]&7;std::memcpy(out.data()+j,y.data()+4*k,4);}}
                else {unsigned w=ext>=0x6c?8:1u<<(ext&3);unsigned start=(ext==0x6d||(ext>=0x68&&ext<=0x6a))?8:0;
                    for(unsigned lane=0;lane<n;lane+=16)for(unsigned j=0;j<8;j+=w){std::memcpy(out.data()+lane+2*j,x.data()+lane+start+j,w);std::memcpy(out.data()+lane+2*j+w,y.data()+lane+start+j,w);}}
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V68: packed integer shifts, immediate and uniform register/memory counts.
            if(map1&&pp==1&&((ext>=0x71&&ext<=0x73)||ext==0xd1||ext==0xd2||ext==0xd3||ext==0xe1||ext==0xe2||ext==0xf1||ext==0xf2||ext==0xf3)) {
                bool immediate=ext>=0x71&&ext<=0x73;
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||(immediate&&!fetch(pc,imm))){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned group=(m>>3)&7, reg=group+((rex&4)?8:0);
                bool byteShift=immediate&&ext==0x73&&(group==3||group==7);
                if(immediate&&(!rm.reg||(!byteShift&&group!=2&&group!=4&&group!=6)||(group==4&&ext==0x73))){s.exit=Cpu64Exit::unsupported;break;}
                unsigned dst=immediate?src:reg, input=immediate?rm.id:src;
                unsigned w=2u<<((ext&15)-1), bits=w*8;
                bool left=immediate?(group==6||group==7):(ext>=0xf1), arithmetic=immediate?group==4:(ext==0xe1||ext==0xe2);
                uint64_t count=imm;
                if(!immediate){std::array<uint8_t,16> c{};if(rm.reg)c=s.xmm[rm.id];else if(memory.read(addressOf(rm),c)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}std::memcpy(&count,c.data(),8);}
                std::array<uint8_t,32> x{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[input][j]:s.ymmHigh[input][j-16];
                if(byteShift){if(count<16)for(unsigned lane=0;lane<n;lane+=16)for(unsigned j=0;j<16;++j){if(left?j>=count:j+count<16)out[lane+j]=x[lane+(left?j-count:j+count)];}}
                else for(unsigned j=0;j<n;j+=w){uint64_t v=0,z=0;std::memcpy(&v,x.data()+j,w);uint64_t mask=~uint64_t(0)>>(64-bits);bool negative=(v>>(bits-1))!=0;
                    if(count>=bits)z=arithmetic&&negative?mask:0;
                    else if(left)z=(v<<count)&mask;
                    else {z=v>>count;if(arithmetic&&negative&&count)z|=mask^(mask>>count);}
                    std::memcpy(out.data()+j,&z,w);
                }
                for(unsigned j=0;j<16;++j){s.xmm[dst][j]=out[j];s.ymmHigh[dst][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V67: scalar flag comparisons and AVX predicate masks.
            if(map1&&(((ext==0x2e||ext==0x2f)&&pp<=1)||ext==0xc2)) {
                bool flags=ext!=0xc2, scalar=flags||pp>=2, dbl=pp==1||pp==3;
                if((scalar&&n!=16)||(flags&&src!=0)){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||(!flags&&!fetch(pc,imm))){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0), w=dbl?8:4, bytes=scalar?w:n;
                std::array<uint8_t,32> x{},y{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[flags?reg:src][j]:s.ymmHigh[src][j-16];
                if(rm.reg){for(unsigned j=0;j<bytes;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(bytes))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                out=x;
                for(unsigned j=0;j<bytes;j+=w){
                    uint64_t u=0,v=0;std::memcpy(&u,x.data()+j,w);std::memcpy(&v,y.data()+j,w);
                    uint64_t exp=dbl?0x7ff0000000000000ull:0x7f800000ull, frac=dbl?0xfffffffffffffull:0x7fffffull, quiet=dbl?0x8000000000000ull:0x400000ull;
                    bool un=(u&exp)==exp&&(u&frac), vn=(v&exp)==exp&&(v&frac), unordered=un||vn;
                    bool signaling=flags?ext==0x2f:((0x99996666u>>(imm&31))&1u)!=0;
                    bool invalid=(un&&!(u&quiet))||(vn&&!(v&quiet))||(unordered&&signaling);
                    if(invalid){s.mxcsr|=1;if(!(s.mxcsr&0x80)){s.exit=Cpu64Exit::unsupported;break;}}
                    double l=0,r=0;
                    if(!unordered){if(dbl){l=std::bit_cast<double>(u);r=std::bit_cast<double>(v);}else{l=std::bit_cast<float>(uint32_t(u));r=std::bit_cast<float>(uint32_t(v));}}
                    bool eq=!unordered&&l==r, lt=!unordered&&l<r, gt=!unordered&&l>r;
                    if(flags){s.zf=unordered||eq;s.pf=unordered;s.cf=unordered||lt;s.of=s.sf=false;}
                    else {unsigned pred=imm&15;bool yes=false;switch(pred){case 0:yes=eq;break;case 1:yes=lt;break;case 2:yes=lt||eq;break;case 3:yes=unordered;break;case 4:yes=!eq;break;case 5:yes=!lt;break;case 6:yes=!(lt||eq);break;case 7:yes=!unordered;break;case 8:yes=eq||unordered;break;case 9:yes=!gt&&!eq;break;case 10:yes=!gt;break;case 11:yes=false;break;case 12:yes=lt||gt;break;case 13:yes=gt||eq;break;case 14:yes=gt;break;case 15:yes=true;break;}std::memset(out.data()+j,yes?255:0,w);}
                }
                if(s.exit==Cpu64Exit::unsupported)break;
                if(!flags)for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V66: signed/unsigned saturating packs and scalar insertion/extraction.
            const bool pack=pp==1&&((map1&&(ext==0x63||ext==0x67||ext==0x6b))||(op==0xc4&&(a&31)==2&&ext==0x2b));
            if(pack||(map3&&pp==1&&(ext==0x21||ext==0x17))) {
                bool extract=!pack&&ext==0x17;
                if(!pack&&(n!=16||(extract&&src!=0))){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||(!pack&&!fetch(pc,imm))){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                if(extract){
                    uint32_t v;std::memcpy(&v,s.xmm[reg].data()+4*(imm&3),4);
                    if(rm.reg)s.gpr[rm.id]=v;
                    else if(memory.write(addressOf(rm),std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&v),4))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                }else{
                    std::array<uint8_t,32> x{},y{},out{};
                    unsigned bytes=pack?n:rm.reg?16:4;
                    for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                    if(rm.reg){for(unsigned j=0;j<bytes;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                    else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(bytes))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                    if(pack){
                        unsigned w=(ext==0x63||ext==0x67)?2:4;bool uns=ext==0x67||ext==0x2b;
                        for(unsigned lane=0;lane<n;lane+=16)for(unsigned j=0;j<32/w;++j){
                            const auto& v=j<16/w?x:y;unsigned off=lane+(j%(16/w))*w;int32_t z;
                            if(w==2){int16_t t;std::memcpy(&t,v.data()+off,2);z=t;}else std::memcpy(&z,v.data()+off,4);
                            int32_t lo=uns?0:w==2?-128:-32768,hi=uns?(w==2?255:65535):(w==2?127:32767);
                            z=z<lo?lo:z>hi?hi:z;uint16_t u=static_cast<uint16_t>(z);
                            if(w==2)out[lane+j]=static_cast<uint8_t>(u);else std::memcpy(out.data()+lane+j*2,&u,2);
                        }
                    }else{out=x;std::memcpy(out.data()+4*((imm>>4)&3),y.data()+(rm.reg?4*(imm>>6):0),4);for(unsigned j=0;j<4;++j)if(imm&(1u<<j))std::memset(out.data()+4*j,0,4);}
                    for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                }
                s.rip=pc;++s.steps;continue;
            }
            // V65: explicit rounding and packed integer conversions.
            if((map3&&pp==1&&ext>=8&&ext<=11)||(map1&&ext==0x5b&&pp<=2)) {
                bool rounding=map3, scalar=rounding&&ext>=10;
                if((!scalar&&src!=0)||(scalar&&n!=16)){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||(rounding&&!fetch(pc,imm))){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0), bytes=scalar?(ext==10?4:8):n;
                std::array<uint8_t,32> y{},out{};
                if(scalar)std::memcpy(out.data(),s.xmm[src].data(),16);
                if(rm.reg){for(unsigned j=0;j<bytes;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(bytes))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned mode=rounding?((imm&4)?((s.mxcsr>>13)&3):(imm&3)):pp==2?3:(s.mxcsr>>13)&3;
                auto roundValue=[&](double v){
                    if(!std::isfinite(v)||v==0)return v;
                    if(mode==1)return std::floor(v);
                    if(mode==2)return std::ceil(v);
                    if(mode==3)return std::trunc(v);
                    double f=std::floor(v), d=v-f;
                    double r=d<0.5?f:d>0.5?f+1:std::fmod(f,2.0)==0?f:f+1;
                    return r==0?std::copysign(0.0,v):r;
                };
                if(rounding){
                    auto calc=[&]<typename T>(){for(unsigned j=0;j<bytes;j+=sizeof(T)){T v{};std::memcpy(&v,y.data()+j,sizeof(T));T z=static_cast<T>(roundValue(v));std::memcpy(out.data()+j,&z,sizeof(T));}};
                    if(ext&1)calc.template operator()<double>();else calc.template operator()<float>();
                }else for(unsigned j=0;j<n;j+=4){
                    if(pp==0){int32_t v;std::memcpy(&v,y.data()+j,4);float z=static_cast<float>(v);std::memcpy(out.data()+j,&z,4);}
                    else {float v;std::memcpy(&v,y.data()+j,4);double r=roundValue(v);int32_t z=std::numeric_limits<int32_t>::min();if(std::isfinite(r)&&r>=-2147483648.0&&r<2147483648.0)z=static_cast<int32_t>(r);std::memcpy(out.data()+j,&z,4);}
                }
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            if((map1&&pp<=1&&(ext==0xc6||ext==0x14||ext==0x15)) ||
               (map1&&pp==1&&ext==0x70) ||
               (map3&&pp==1&&(ext==0x04||ext==0x05||ext==0x0c||ext==0x0d||ext==0x0e))) {
                bool unary=ext==0x70||(map3&&(ext==4||ext==5));
                if(unary&&src!=0){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                uint8_t imm=0;
                if((ext!=0x14&&ext!=0x15)&&!fetch(pc,imm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                std::array<uint8_t,32> x{},y{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                if(rm.reg){for(unsigned j=0;j<n;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned w=map3?(ext==5||ext==0x0d?8:ext==0x0e?2:4):ext==0x70?4:pp==1?8:4;
                unsigned count=16/w;
                for(unsigned lane=0;lane<n;lane+=16){
                    for(unsigned j=0;j<count;++j){
                        unsigned k=j;bool useY=false;
                        if(ext==0x14||ext==0x15){k=j/2+(ext==0x15?count/2:0);useY=j%2;}
                        else if(ext==0xc6){useY=j>=count/2;k=w==4?(imm>>(2*j))&3:(imm>>(lane/8+j))&1;}
                        else if(unary){useY=true;k=w==4?(imm>>(2*j))&3:(imm>>(lane/8+j))&1;}
                        else {unsigned bit=ext==0x0e?j:lane/w+j;useY=(imm>>bit)&1;}
                        const auto& v=useY?y:x;
                        std::memcpy(out.data()+lane+j*w,v.data()+lane+k*w,w);
                    }
                }
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V63: FMA3, all operand orders, packed and scalar forms.
            if(op==0xc4 && (a&31)==2 && pp==1 &&
               (ext>>4)>=9 && (ext>>4)<=11 && (ext&15)>=6) {
                unsigned kind=ext&15, order=ext>>4;
                bool scalar=kind>=8 && (kind&1), wideDouble=b&128;
                if(scalar && n==32){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                unsigned bytes=scalar?(wideDouble?8:4):n;
                std::array<uint8_t,32> d{},x{},y{},out{};
                for(unsigned j=0;j<n;++j){d[j]=j<16?s.xmm[reg][j]:s.ymmHigh[reg][j-16];x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];}
                out=d;
                if(rm.reg){for(unsigned j=0;j<bytes;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(bytes))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                auto calc=[&]<typename T>() {
                    for(unsigned j=0;j<bytes;j+=sizeof(T)){
                        T u{},v{},w{};
                        std::memcpy(&u,d.data()+j,sizeof(T));std::memcpy(&v,x.data()+j,sizeof(T));std::memcpy(&w,y.data()+j,sizeof(T));
                        T l=order==11?v:u, r=order==9?w:order==10?v:w, c=order==9?v:order==10?w:u;
                        bool subtract=kind==6?(j/sizeof(T))%2==0:kind==7?(j/sizeof(T))%2!=0:kind==10||kind==11||kind==14||kind==15;
                        if(kind>=12)l=-l;
                        if(subtract)c=-c;
                        T z=std::fma(l,r,c);
                        std::memcpy(out.data()+j,&z,sizeof(T));
                    }
                };
                if(wideDouble)calc.template operator()<double>();else calc.template operator()<float>();
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V62: packed floating arithmetic; host rounding, approximate reciprocal.
            if((op==0xc5||(a&31)==1) && pp<=1 &&
               (ext==0x51 || (pp==0&&(ext==0x52||ext==0x53)) ||
                ext==0x58||ext==0x59||ext==0x5c||ext==0x5e)) {
                bool unary=ext<=0x53;
                if(unary&&src!=0){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                std::array<uint8_t,32> x{},y{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                if(rm.reg){for(unsigned j=0;j<n;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                auto calc=[&]<typename T>() {
                    for(unsigned j=0;j<n;j+=sizeof(T)){
                        T l{},r{},z{};
                        std::memcpy(&l,x.data()+j,sizeof(T));std::memcpy(&r,y.data()+j,sizeof(T));
                        switch(ext){case 0x51:z=std::sqrt(r);break;case 0x52:case 0x53:
                            if(std::fpclassify(r)==FP_SUBNORMAL)r=std::copysign(T(0),r);
                            z=ext==0x52?T(1)/std::sqrt(r):T(1)/r;
                            if(std::fpclassify(z)==FP_SUBNORMAL)z=std::copysign(T(0),z);
                            break;
                            case 0x58:z=l+r;break;case 0x59:z=l*r;break;case 0x5c:z=l-r;break;case 0x5e:z=l/r;break;}
                        std::memcpy(out.data()+j,&z,sizeof(T));
                    }
                };
                if(pp==1)calc.template operator()<double>();else calc.template operator()<float>();
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V61: lane-local horizontal floating-point arithmetic.
            if((op==0xc5||(a&31)==1)&&(pp==1||pp==3)&&(ext==0x7c||ext==0x7d||ext==0xd0)) {
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                std::array<uint8_t,32> x{},y{},out{};
                for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                if(rm.reg){for(unsigned j=0;j<n;++j)y[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(y).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                auto calc=[&]<typename T>() {
                    constexpr unsigned count=16/sizeof(T);
                    for(unsigned lane=0;lane<n;lane+=16){
                        for(unsigned j=0;j<count;++j){
                            T l{},r{},z{};
                            if(ext==0xd0){std::memcpy(&l,x.data()+lane+j*sizeof(T),sizeof(T));std::memcpy(&r,y.data()+lane+j*sizeof(T),sizeof(T));z=j%2?l+r:l-r;}
                            else {const auto& v=j<count/2?x:y;unsigned k=(j%(count/2))*2;std::memcpy(&l,v.data()+lane+k*sizeof(T),sizeof(T));std::memcpy(&r,v.data()+lane+(k+1)*sizeof(T),sizeof(T));z=ext==0x7c?l+r:l-r;}
                            std::memcpy(out.data()+lane+j*sizeof(T),&z,sizeof(T));
                        }
                    }
                };
                if(pp==1)calc.template operator()<double>();else calc.template operator()<float>();
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V46: AVX2 scalar broadcasts and lane-local byte shuffle.
            if(op==0xc4 && (a&31)==2 && pp==1 &&
               (ext==0x18||ext==0x19||ext==0x1a||ext==0x78||ext==0x79||ext==0x58||ext==0x59||ext==0x00||ext==0x40)) {
                const bool broadcast=ext!=0x00&&ext!=0x40;
                if(broadcast&&src!=0){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                if((ext==0x19||ext==0x1a)&&n!=32){s.exit=Cpu64Exit::unsupported;break;}
                if(ext==0x1a&&rm.reg){s.exit=Cpu64Exit::unsupported;break;}
                unsigned w=ext==0x78?1:ext==0x79?2:(ext==0x58||ext==0x18)?4:(ext==0x59||ext==0x19)?8:ext==0x1a?16:n;
                std::array<uint8_t,32> v{},out{},x{};
                if(rm.reg){for(unsigned j=0;j<w;++j)v[j]=j<16?s.xmm[rm.id][j]:s.ymmHigh[rm.id][j-16];}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(v).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                if(broadcast){for(unsigned j=0;j<n;++j)out[j]=v[j%w];}
                else {
                    for(unsigned j=0;j<n;++j)x[j]=j<16?s.xmm[src][j]:s.ymmHigh[src][j-16];
                    if(ext==0x00){for(unsigned j=0;j<n;++j)out[j]=(v[j]&128)?0:x[(j&~15u)+(v[j]&15)];}
                    else {for(unsigned j=0;j<n;j+=4){uint32_t l=0,r=0;for(unsigned k=0;k<4;++k){l|=uint32_t(x[j+k])<<(8*k);r|=uint32_t(v[j+k])<<(8*k);}uint32_t z=l*r;for(unsigned k=0;k<4;++k)out[j+k]=uint8_t(z>>(8*k));}}
                }
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=n==32?out[j+16]:0;}
                s.rip=pc;++s.steps;continue;
            }
            // V53: BMI2 MULX, variable shifts, PDEP and PEXT.
            if(op==0xc4 && (a&31)==2 && n==16 &&
               ((ext==0xf6 && pp==3)||(ext==0xf7 && pp!=0)||(ext==0xf5 && pp>=2))) {
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0), w=(b&128)?8:4;
                uint64_t v=0;
                if(rm.reg)v=readReg(rm.id,w);
                else {std::array<uint8_t,8> bytes{};if(memory.read(addressOf(rm),std::span<uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}for(unsigned j=0;j<w;++j)v|=uint64_t(bytes[j])<<(8*j);}
                uint64_t x=readReg(src,w), z=0;
                if(ext==0xf6){
                    __uint128_t product=__uint128_t(readReg(2,w))*v;
                    writeReg(src,w,uint64_t(product));writeReg(reg,w,uint64_t(product>>(w*8)));
                }else if(ext==0xf7){
                    unsigned k=x&(w*8-1);
                    if(pp==1)z=v<<k;
                    else if(pp==3)z=v>>k;
                    else {z=v>>k;if(k&&(v>>(w*8-1)))z|=(~0ull)<<(w*8-k);}
                    writeReg(reg,w,z);
                }else {
                    unsigned j=0;
                    for(unsigned k=0;k<w*8;++k)if((v>>k)&1){if(pp==2)z|=((x>>k)&1)<<j;else z|=((x>>j)&1)<<k;++j;}
                    writeReg(reg,w,z);
                }
                s.rip=pc;++s.steps;continue;
            }
            if(op==0xc4 && (a&31)==2) {
                if(n!=16 || pp!=0 || (ext!=0xf3 && ext!=0xf2 && ext!=0xf7)) {s.exit=Cpu64Exit::unsupported;break;}
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned group=(m>>3)&7, reg=group+((rex&4)?8:0), w=(b&128)?8:4;
                if(ext==0xf3&&(group<1||group>3)){s.exit=Cpu64Exit::unsupported;break;}
                uint64_t mask=w==8?~0ull:0xffffffffull, v=0;
                if(rm.reg)v=readReg(rm.id,w);
                else {std::array<uint8_t,8> bytes{};if(memory.read(addressOf(rm),std::span<uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}for(unsigned j=0;j<w;++j)v|=uint64_t(bytes[j])<<(8*j);}
                uint64_t z=0; unsigned dest=reg;
                if(ext==0xf3){dest=src;z=group==1?v&(v-1):group==2?v^(v-1):v&(-v);s.cf=group==3?v!=0:v==0;}
                else if(ext==0xf2){z=(~readReg(src,w))&v;s.cf=false;}
                else {auto ctl=readReg(src,w);unsigned start=ctl&255,len=(ctl>>8)&255; if(start<w*8){len=std::min(len,w*8-start);z=(v>>start)&(len==64?~0ull:((1ull<<len)-1));}s.cf=false;}
                z&=mask;writeReg(dest,w,z);s.zf=z==0;s.of=false;if(ext!=0xf7)s.sf=(z>>(w*8-1))!=0;
                s.rip=pc;++s.steps;continue;
            }
            // V56: BMI2 RORX, preserving all flags.
            if(op==0xc4 && (a&31)==3 && ext==0xf0 && pp==3 && n==16 && src==0) {
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||!fetch(pc,imm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0), w=(b&128)?8:4;
                uint64_t v=0;
                if(rm.reg)v=readReg(rm.id,w);
                else {std::array<uint8_t,8> bytes{};if(memory.read(addressOf(rm),std::span<uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}for(unsigned j=0;j<w;++j)v|=uint64_t(bytes[j])<<(8*j);}
                unsigned bits=w*8, k=imm&(bits-1);
                uint64_t z=k?((v>>k)|(v<<(bits-k))):v;
                writeReg(reg,w,z);s.rip=pc;++s.steps;continue;
            }
            // V47: immediate full-width permutations and lane selection.
            if(op==0xc4 && (a&31)==3 && pp==1 && n==32 &&
               (((ext==0x00||ext==0x01)&&(b&128)&&src==0)||(ext==0x46&&!(b&128)))) {
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||!fetch(pc,imm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                std::array<uint8_t,32> v{},out{},x{};
                if(rm.reg){for(unsigned j=0;j<16;++j){v[j]=s.xmm[rm.id][j];v[j+16]=s.ymmHigh[rm.id][j];}}
                else if(memory.read(addressOf(rm),v)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                if(ext==0x46){
                    for(unsigned j=0;j<16;++j){x[j]=s.xmm[src][j];x[j+16]=s.ymmHigh[src][j];}
                    for(unsigned lane=0;lane<2;++lane){unsigned ctl=(imm>>(lane*4))&15;if(!(ctl&8)){const auto& from=(ctl&2)?v:x;for(unsigned j=0;j<16;++j)out[lane*16+j]=from[(ctl&1)*16+j];}}
                }else for(unsigned lane=0;lane<4;++lane)for(unsigned j=0;j<8;++j)out[lane*8+j]=v[((imm>>(lane*2))&3)*8+j];
                for(unsigned j=0;j<16;++j){s.xmm[reg][j]=out[j];s.ymmHigh[reg][j]=out[j+16];}
                s.rip=pc;++s.steps;continue;
            }
            if(op==0xc4 && (a&31)==3) {
                const bool extract=ext==0x14||ext==0x15||ext==0x16||ext==0x17;
                const bool insert=ext==0x20||ext==0x22;
                if(pp!=1||n!=16||(!extract&&!insert)||(extract&&src!=0)){s.exit=Cpu64Exit::unsupported;break;}
                Operand rm; uint8_t imm=0;
                if(!fetch(pc,m)||!decodeRM(m,rm)||!fetch(pc,imm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                unsigned w=(ext==0x14||ext==0x20)?1:ext==0x15?2:(ext==0x16||ext==0x22)&&(b&128)?8:4;
                unsigned off=(imm%(16/w))*w;
                std::array<uint8_t,8> bytes{};
                if(extract){
                    uint64_t v=0;for(unsigned j=0;j<w;++j){bytes[j]=s.xmm[reg][off+j];v|=uint64_t(bytes[j])<<(8*j);}
                    if(rm.reg)writeReg(rm.id,w==8?8:4,v);
                    else if(memory.write(addressOf(rm),std::span<const uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                }else{
                    if(rm.reg){auto v=readReg(rm.id,w==8?8:4);for(unsigned j=0;j<w;++j)bytes[j]=uint8_t(v>>(8*j));}
                    else if(memory.read(addressOf(rm),std::span<uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                    auto v=s.xmm[src];for(unsigned j=0;j<w;++j)v[off+j]=bytes[j];s.xmm[reg]=v;s.ymmHigh[reg].fill(0);
                }
                s.rip=pc;++s.steps;continue;
            }
            if(ext==0x77 && pp==0 && src==0) {
                for(unsigned i=0;i<16;++i) {s.ymmHigh[i].fill(0);if(n==32)s.xmm[i].fill(0);}
                s.rip=pc;++s.steps;continue;
            }
            // V55: VEX half-vector moves and register merges.
            if(n==16 && pp<=1 && (ext==0x12||ext==0x13||ext==0x16||ext==0x17)) {
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                bool high=ext>=0x16, store=(ext&1)!=0;
                std::array<uint8_t,8> bytes{};
                if(store){
                    if(rm.reg||src!=0){s.exit=Cpu64Exit::unsupported;break;}
                    for(unsigned j=0;j<8;++j)bytes[j]=s.xmm[reg][j+(high?8:0)];
                    if(memory.write(addressOf(rm),bytes)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                }else{
                    if(rm.reg){if(pp){s.exit=Cpu64Exit::unsupported;break;}for(unsigned j=0;j<8;++j)bytes[j]=s.xmm[rm.id][j+(high?0:8)];}
                    else if(memory.read(addressOf(rm),bytes)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                    auto out=s.xmm[src];for(unsigned j=0;j<8;++j)out[j+(high?8:0)]=bytes[j];
                    s.xmm[reg]=out;s.ymmHigh[reg].fill(0);
                }
                s.rip=pc;++s.steps;continue;
            }
            // V58: scalar floating arithmetic and signed integer conversion.
            // Host default rounding; guest MXCSR exceptions are not modeled.
            if((op==0xc5||(a&31)==1)&&n==16&&pp>=2&&
               (ext==0x2a||ext==0x58||ext==0x59||ext==0x5c||ext==0x5e)) {
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0);
                unsigned w=ext==0x2a?((op==0xc4&&(b&0x80))?8:4):(pp==2?4:8);
                std::array<uint8_t,8> bytes{};
                if(rm.reg){if(ext==0x2a){auto v=s.gpr[rm.id];for(unsigned j=0;j<w;++j)bytes[j]=uint8_t(v>>(8*j));}
                    else std::memcpy(bytes.data(),s.xmm[rm.id].data(),w);}
                else if(memory.read(addressOf(rm),std::span<uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                auto out=s.xmm[src];
                auto calculate=[&]<typename T>(){
                    T x{},y{},z{};
                    if(ext==0x2a){if(w==8){int64_t v;std::memcpy(&v,bytes.data(),8);z=static_cast<T>(v);}else{int32_t v;std::memcpy(&v,bytes.data(),4);z=static_cast<T>(v);}}
                    else {std::memcpy(&x,out.data(),sizeof(T));std::memcpy(&y,bytes.data(),sizeof(T));
                        switch(ext){case 0x58:z=x+y;break;case 0x59:z=x*y;break;case 0x5c:z=x-y;break;case 0x5e:z=x/y;break;}}
                    std::memcpy(out.data(),&z,sizeof(T));
                };
                if(pp==2)calculate.template operator()<float>();else calculate.template operator()<double>();
                s.xmm[reg]=out;s.ymmHigh[reg].fill(0);s.rip=pc;++s.steps;continue;
            }
            // V57: scalar AVX moves, memory loads zero upper lanes.
            if(n==16 && pp>=2 && (ext==0x10||ext==0x11)) {
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned reg=((m>>3)&7)+((rex&4)?8:0), w=pp==2?4:8;
                if(!rm.reg && src!=0){s.exit=Cpu64Exit::unsupported;break;}
                if(rm.reg){
                    auto out=s.xmm[src]; auto low=s.xmm[ext==0x10?rm.id:reg];
                    unsigned dest=ext==0x10?reg:rm.id;
                    for(unsigned j=0;j<w;++j)out[j]=low[j];
                    s.xmm[dest]=out;s.ymmHigh[dest].fill(0);
                }else if(ext==0x10){
                    std::array<uint8_t,16> out{};
                    if(memory.read(addressOf(rm),std::span<uint8_t>(out).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                    s.xmm[reg]=out;s.ymmHigh[reg].fill(0);
                }else if(memory.write(addressOf(rm),std::span<const uint8_t>(s.xmm[reg]).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                s.rip=pc;++s.steps;continue;
            }
            const bool fpMove=pp<=1 && (ext==0x28||ext==0x29||ext==0x10||ext==0x11);
            const bool intMove=(pp==1||pp==2)&&(ext==0x6f||ext==0x7f);
            const bool fpLogic=pp<=1 && ext>=0x54 && ext<=0x57;
            const bool intLogic=pp==1 && (ext==0xef||ext==0xdb||ext==0xeb||ext==0xdf);
            const bool packed=pp==1 && (ext==0xfc||ext==0xfd||ext==0xfe||ext==0xd4||ext==0xf8||ext==0xf9||ext==0xfa||ext==0xfb||ext==0xd5||ext==0x74||ext==0x75||ext==0x76);
            const bool scalarInt=pp==1&&(ext==0x6e||ext==0x7e)&&n==16;
            const bool scalarQ=pp==2&&ext==0x7e&&n==16;
            const bool move=fpMove||intMove||scalarInt||scalarQ;
            if((!move&&!fpLogic&&!intLogic&&!packed)||(move&&src!=0)) {s.exit=Cpu64Exit::unsupported;break;}
            Operand rm;
            if(!fetch(pc,m)||!decodeRM(m,rm)) {s.exit=Cpu64Exit::memoryFault;break;}
            const unsigned reg=((m>>3)&7)+((rex&4)?8:0);
            const uint64_t addr=addressOf(rm);
            if(scalarInt||scalarQ) {
                unsigned w=scalarQ||(op==0xc4&&(b&0x80))?8:4;
                std::array<uint8_t,8> bytes{};
                if(scalarInt&&ext==0x7e) {
                    for(unsigned j=0;j<w;++j)bytes[j]=s.xmm[reg][j];
                    if(rm.reg){uint64_t v=0;for(unsigned j=0;j<w;++j)v|=uint64_t(bytes[j])<<(8*j);writeReg(rm.id,w,v);}
                    else if(memory.write(addr,std::span<const uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                } else {
                    if(rm.reg){if(scalarQ){for(unsigned j=0;j<w;++j)bytes[j]=s.xmm[rm.id][j];}else{auto v=readReg(rm.id,w);for(unsigned j=0;j<w;++j)bytes[j]=uint8_t(v>>(8*j));}}
                    else if(memory.read(addr,std::span<uint8_t>(bytes).first(w))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                    s.xmm[reg].fill(0);s.ymmHigh[reg].fill(0);for(unsigned j=0;j<w;++j)s.xmm[reg][j]=bytes[j];
                }
                s.rip=pc;++s.steps;continue;
            }
            const bool aligned=(fpMove&&(ext==0x28||ext==0x29))||(intMove&&pp==1);
            if(!rm.reg&&aligned&&(addr&(n-1))) {s.exit=Cpu64Exit::memoryFault;break;}
            auto getVec=[&](unsigned r) {std::array<uint8_t,32> v{};for(unsigned i=0;i<16;++i){v[i]=s.xmm[r][i];if(n==32)v[i+16]=s.ymmHigh[r][i];}return v;};
            auto putVec=[&](unsigned r,const std::array<uint8_t,32>& v) {for(unsigned i=0;i<16;++i){s.xmm[r][i]=v[i];s.ymmHigh[r][i]=n==32?v[i+16]:0;}};
            if(move&&(ext==0x29||ext==0x11||ext==0x7f)) {
                auto v=getVec(reg);
                if(rm.reg)putVec(rm.id,v);
                else if(memory.write(addr,std::span<const uint8_t>(v.data(),n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
            } else {
                std::array<uint8_t,32> v{};
                if(rm.reg)v=getVec(rm.id);
                else if(memory.read(addr,std::span<uint8_t>(v.data(),n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                if(packed){
                    auto x=getVec(src);
                    unsigned w=(ext==0xfc||ext==0xf8||ext==0x74)?1:(ext==0xfd||ext==0xf9||ext==0xd5||ext==0x75)?2:(ext==0xfe||ext==0xfa||ext==0x76)?4:8;
                    for(unsigned i=0;i<n;i+=w){uint64_t a=0,b=0;for(unsigned j=0;j<w;++j){a|=uint64_t(x[i+j])<<(8*j);b|=uint64_t(v[i+j])<<(8*j);}
                    uint64_t z=ext==0xd5?a*b:(ext>=0x74&&ext<=0x76)?(a==b?~uint64_t(0):0):(ext>=0xf8&&ext<=0xfb)?a-b:a+b;
                    for(unsigned j=0;j<w;++j)v[i+j]=uint8_t(z>>(8*j));}
                } else if(!move){auto x=getVec(src);for(unsigned i=0;i<n;++i){if(ext==0x57||ext==0xef)v[i]^=x[i];else if(ext==0x54||ext==0xdb)v[i]&=x[i];else if(ext==0x56||ext==0xeb)v[i]|=x[i];else v[i]&=uint8_t(~x[i]);}}
                putVec(reg,v);
            }
            s.rip=pc;++s.steps;continue;
        }
        if(simdPrefix==0x66 && op!=0x0f && !(op>=0x90 && op<=0x99) && op!=0x86 && op!=0x87 && op!=0xf6 && op!=0xf7 && op!=0xff && op!=0xfe &&
           !((op<0x40 && (op&7)<=5) || op==0x80 || op==0x81 || op==0x83 ||
             op==0x84 || op==0x85 || op==0xa8 || op==0xa9 ||
             (op>=0xb0 && op<=0xbf) || (op>=0x88 && op<=0x8b) ||
             op==0x8d || op==0xc6 || op==0xc7 || op==0x69 || op==0x6b || op==0xc0 || op==0xc1 || (op>=0xd0 && op<=0xd3))) {
            s.exit=Cpu64Exit::unsupported;break;
        }
        // V38: bit scan/count and population count.
        if(op==0x0f && (simdPrefix==0 || simdPrefix==0x66 || simdPrefix==0xf3)) {
            auto saved=pc; uint8_t ext=0;
            if(!fetch(pc,ext)){s.exit=Cpu64Exit::memoryFault;break;}
            if(ext==0xbc || ext==0xbd || (ext==0xb8 && simdPrefix==0xf3)) {
                if(locked){s.exit=Cpu64Exit::unsupported;break;}
                uint8_t m=0; Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned n=(rex&8)?8:simdPrefix==0x66?2:4, bits=n*8;
                uint64_t v=0;
                if(rm.reg)v=readReg(rm.id,n);else {std::array<uint8_t,8>b{};if(memory.read(addressOf(rm),std::span<uint8_t>(b).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}for(unsigned j=0;j<n;++j)v|=uint64_t(b[j])<<(8*j);}
                unsigned dest=((m>>3)&7)+((rex&4)?8:0);
                unsigned leading=std::countl_zero(v)-(64-bits), trailing=v?std::countr_zero(v):bits;
                if(ext==0xb8){writeReg(dest,n,std::popcount(v));s.zf=!v;s.cf=s.of=s.sf=s.pf=false;}
                else if(simdPrefix==0xf3){unsigned result=ext==0xbd?leading:trailing;writeReg(dest,n,result);s.cf=!v;s.zf=!result;}
                else {s.zf=!v;if(v)writeReg(dest,n,ext==0xbd?bits-1-leading:trailing);}
                s.rip=pc;++s.steps;continue;
            }
            pc=saved;
        }
        // V59: two-operand signed IMUL (16/32/64-bit).
        if(op==0x0f && (simdPrefix==0 || simdPrefix==0x66)) {
            auto saved=pc; uint8_t ext=0;
            if(!fetch(pc,ext)){s.exit=Cpu64Exit::memoryFault;break;}
            if(ext==0xaf) {
                if(locked){s.exit=Cpu64Exit::unsupported;break;}
                uint8_t m=0; Operand rm{};
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned n=(rex&8)?8:simdPrefix==0x66?2:4;
                unsigned dst=((m>>3)&7)+((rex&4)?8:0);
                uint64_t v=0;
                if(rm.reg)v=readReg(rm.id,n);
                else {std::array<uint8_t,8>b{};if(memory.read(addressOf(rm),std::span<uint8_t>(b).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}for(unsigned j=0;j<n;++j)v|=uint64_t(b[j])<<(8*j);}
                auto sx=[n](uint64_t x)->__int128 {__int128 y=x;if(x&(uint64_t(1)<<(n*8-1)))y-=(__int128(1)<<(n*8));return y;};
                auto product=sx(readReg(dst,n))*sx(v);
                uint64_t result=uint64_t(product)&(n==8?~uint64_t(0):(uint64_t(1)<<(n*8))-1);
                s.cf=s.of=product!=sx(result);
                writeReg(dst,n,result);s.rip=pc;++s.steps;continue;
            }
            pc=saved;
        }
        // V32: bit-test family, including signed memory bit offsets.
        if(op==0x0f && (simdPrefix==0 || simdPrefix==0x66)) {
            uint64_t saved=pc; uint8_t ext=0;
            if(!fetch(pc,ext)){s.exit=Cpu64Exit::memoryFault;break;}
            if(ext==0xa3 || ext==0xab || ext==0xb3 || ext==0xbb || ext==0xba) {
                uint8_t m=0; Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)){s.exit=Cpu64Exit::memoryFault;break;}
                unsigned n=(rex&8)?8:simdPrefix==0x66?2:4, bits=n*8;
                unsigned kind=ext==0xba?(m>>3)&7:ext==0xa3?4:ext==0xab?5:ext==0xb3?6:7;
                if(kind<4 || (locked&&(rm.reg||kind==4))){s.exit=Cpu64Exit::unsupported;break;}
                uint64_t idx=0;
                if(ext==0xba){uint8_t b=0;if(!fetch(pc,b)){s.exit=Cpu64Exit::memoryFault;break;}idx=b;}
                else {idx=s.gpr[((m>>3)&7)+((rex&4)?8:0)];if(!rm.reg){int64_t k=n==8?int64_t(idx):n==4?int64_t(int32_t(idx)):int64_t(int16_t(idx));int64_t q=k/int64_t(bits);if(k%int64_t(bits)<0)--q;rm.addr+=uint64_t(q)*n;}}
                uint64_t mask=uint64_t(1)<<(idx%bits),v=0;
                if(rm.reg)v=s.gpr[rm.id];else {std::array<uint8_t,8>b{};if(memory.read(addressOf(rm),std::span<uint8_t>(b).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}for(unsigned j=0;j<n;++j)v|=uint64_t(b[j])<<(8*j);}
                bool carry=(v&mask)!=0;
                if(kind!=4){v=kind==5?v|mask:kind==6?v&~mask:v^mask;if(rm.reg){if(n==2)s.gpr[rm.id]=(s.gpr[rm.id]&~0xffffull)|(v&0xffff);else s.gpr[rm.id]=n==4?uint32_t(v):v;}else{std::array<uint8_t,8>b{};for(unsigned j=0;j<n;++j)b[j]=uint8_t(v>>(8*j));if(memory.write(addressOf(rm),std::span<const uint8_t>(b).first(n))!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}}}
                s.cf=carry;s.rip=pc;++s.steps;continue;
            }
            pc=saved;
        }
        // V11: legacy SSE2 128-bit moves and bitwise operations.
        if(simdPrefix && (simdPrefix!=0x66 || op==0x0f) && !locked) {
            uint8_t ext=0,m=0;
            if(locked || op!=0x0f) {s.exit=Cpu64Exit::unsupported;break;}
            if(!fetch(pc,ext)) {s.exit=Cpu64Exit::memoryFault;break;}
            const bool move=(simdPrefix==0x66 || simdPrefix==0xf3) && (ext==0x6f || ext==0x7f);
            const bool logic=simdPrefix==0x66 && (ext==0xef || ext==0xdb || ext==0xeb || ext==0xdf);
            if(!move && !logic) {s.exit=Cpu64Exit::unsupported;break;}
            Operand rm;
            if(!fetch(pc,m)||!decodeRM(m,rm)) {s.exit=Cpu64Exit::memoryFault;break;}
            const unsigned reg=((m>>3)&7)+((rex&4)?8:0);
            const uint64_t addr=addressOf(rm);
            if(!rm.reg && simdPrefix==0x66 && (addr&15)) {s.exit=Cpu64Exit::memoryFault;break;}
            if(move && ext==0x7f) {
                if(rm.reg) s.xmm[rm.id]=s.xmm[reg];
                else if(memory.write(addr,s.xmm[reg])!=GuestMemory64::Fault::none) {s.exit=Cpu64Exit::memoryFault;break;}
            } else {
                std::array<uint8_t,16> value{};
                if(rm.reg) value=s.xmm[rm.id];
                else if(memory.read(addr,value)!=GuestMemory64::Fault::none) {s.exit=Cpu64Exit::memoryFault;break;}
                if(move) s.xmm[reg]=value;
                else for(unsigned i=0;i<16;++i) {
                    auto &a=s.xmm[reg][i];
                    if(ext==0xef) a^=value[i];
                    else if(ext==0xdb) a&=value[i];
                    else if(ext==0xeb) a|=value[i];
                    else a=uint8_t(~a)&value[i];
                }
            }
            s.rip=pc;++s.steps;continue;
        }


        auto readOp = [&](const Operand& o,unsigned n,uint64_t& v)->bool {
            if(o.reg) {
                v=readReg(o.id,n);
                return true;
            }
            std::array<uint8_t,8> bytes{};
            if(memory.read(addressOf(o),
                std::span<uint8_t>(bytes.data(),n))
                !=GuestMemory64::Fault::none) return false;
            v=0;
            for(unsigned i=0;i<n;++i)
                v|=uint64_t(bytes[i])<<(i*8);
            return true;
        };

        auto writeOp = [&](const Operand& o,unsigned n,uint64_t v)->bool {
            if(o.reg) {
                writeReg(o.id,n,v);
                return true;
            }
            std::array<uint8_t,8> bytes{};
            for(unsigned i=0;i<n;++i)
                bytes[i]=uint8_t(v>>(i*8));
            return memory.write(addressOf(o),
                std::span<const uint8_t>(bytes.data(),n))
                ==GuestMemory64::Fault::none;
        };

        auto condition = [&](unsigned c)->bool {
            switch(c&15) {
                case 0: return s.of;
                case 1: return !s.of;
                case 2: return s.cf;
                case 3: return !s.cf;
                case 4: return s.zf;
                case 5: return !s.zf;
                case 6: return s.cf||s.zf;
                case 7: return !s.cf&&!s.zf;
                case 8: return s.sf;
                case 9: return !s.sf;
                case 10: return s.pf;
                case 11: return !s.pf;
                case 12: return s.sf!=s.of;
                case 13: return s.sf==s.of;
                case 14: return s.zf||s.sf!=s.of;
                default: return !s.zf&&s.sf==s.of;
            }
        };


        // ALIEN_UNIFIED_ALU_V3

        auto alu = [&](unsigned group,unsigned n,
                       uint64_t a,uint64_t b)->uint64_t {

            const uint64_t mask=maskFor(n);
            const uint64_t sign=uint64_t(1)<<(n*8-1);

            a &= mask;
            b &= mask;

            const uint64_t carry=s.cf?1:0;
            uint64_t result=0;

            switch(group) {
                case 0: // ADD
                case 2: { // ADC
                    uint64_t c=group==2?carry:0;
                    uint64_t t=(a+b)&mask;
                    result=(t+c)&mask;
                    s.cf=(t<a)||(result<t);
                    s.of=(~(a^b)&(a^result)&sign)!=0;
                    break;
                }

                case 3: // SBB
                case 5: // SUB
                case 7: { // CMP
                    uint64_t c=group==3?carry:0;
                    uint64_t t=(a-b)&mask;
                    result=(t-c)&mask;
                    s.cf=(a<b)||(t<c);
                    s.of=((a^b)&(a^result)&sign)!=0;
                    break;
                }

                case 1: // OR
                    result=a|b;
                    s.cf=false;
                    s.of=false;
                    break;

                case 4: // AND / TEST
                    result=a&b;
                    s.cf=false;
                    s.of=false;
                    break;

                case 6: // XOR
                    result=a^b;
                    s.cf=false;
                    s.of=false;
                    break;
            }

            result &= mask;

            s.zf=result==0;
            s.sf=(result&sign)!=0;

            uint8_t low=uint8_t(result);
            low^=low>>4;
            low^=low>>2;
            low^=low>>1;
            s.pf=(low&1)==0;

            return result;
        };

        // V71: locked read-modify-write in the serialized guest interpreter.
        // GuestMemory64 is not thread-safe; concurrent guest execution is not supported.
        if(locked) {
            uint8_t ext=0,m=0; Operand dst{};
            if(op==0x0f && !fetch(pc,ext)){s.exit=Cpu64Exit::memoryFault;break;}
            if(!fetch(pc,m)||!decodeRM(m,dst)){s.exit=Cpu64Exit::memoryFault;break;}
            unsigned g=(m>>3)&7, r=g+((rex&4)?8:0);
            unsigned n=(rex&8)?8:simdPrefix==0x66?2:4;
            uint64_t b=0,a=0; unsigned kind=0;
            if(op<0x40 && op!=0x0f){g=(op>>3)&7;if(g==7){s.exit=Cpu64Exit::unsupported;break;}if(!(op&1))n=1;b=readReg(r,n);}
            else if(op==0x80||op==0x81||op==0x83){if(g==7){s.exit=Cpu64Exit::unsupported;break;}if(op==0x80)n=1;if(!readImm(op==0x83?1:n==8?4:n,b)){s.exit=Cpu64Exit::memoryFault;break;}if(op==0x83)b=uint64_t(int64_t(int8_t(b)));else if(n==8)b=uint64_t(int64_t(int32_t(b)));}
            else if((op==0xfe||op==0xff)&&g<=1){if(op==0xfe)n=1;kind=1;b=1;g=g?5:0;}
            else if((op==0xf6||op==0xf7)&&(g==2||g==3)){if(op==0xf6)n=1;kind=g==2?2:3;}
            else if(op==0x86||op==0x87){if(op==0x86)n=1;kind=4;b=readReg(r,n);}
            else if(op==0x0f&&(ext==0xc0||ext==0xc1||ext==0xb0||ext==0xb1)){if(!(ext&1))n=1;kind=ext>=0xc0?5:6;b=readReg(r,n);}
            else {s.exit=Cpu64Exit::unsupported;break;}
            if(dst.reg){s.exit=Cpu64Exit::unsupported;break;}
            if(!readOp(dst,n,a)){s.exit=Cpu64Exit::memoryFault;break;}
            auto old=s;uint64_t z=0;
            switch(kind){case 0:z=alu(g,n,a,b);break;case 1:z=alu(g,n,a,b);s.cf=old.cf;break;case 2:z=~a;break;case 3:z=alu(5,n,0,a);break;case 4:z=b;break;case 5:z=alu(0,n,a,b);break;default:alu(7,n,readReg(0,n),a);z=s.zf?b:a;break;}
            if(!writeOp(dst,n,z)){s=old;s.exit=Cpu64Exit::memoryFault;break;}
            if(kind==4||kind==5)writeReg(r,n,a);else if(kind==6&&!s.zf)writeReg(0,n,a);
            s.rip=pc;++s.steps;continue;
        }
        // ADD OR ADC SBB AND SUB XOR CMP
        // Register, memory and accumulator forms.
        if(op<0x40 && (op&7)<=5) {

            unsigned group=(op>>3)&7;
            unsigned form=op&7;
            unsigned n=(form&1)?((rex&8)?8:(simdPrefix==0x66?2:4)):1;

            uint64_t a=0,b=0;
            Operand dst;

            if(form<=3) {
                uint8_t m=0;
                Operand rm;

                if(!fetch(pc,m)||!decodeRM(m,rm)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                Operand reg;
                reg.reg=true;
                reg.id=((m>>3)&7)+((rex&4)?8:0);

                dst=(form&2)?reg:rm;
                Operand src=(form&2)?rm:reg;

                if(!readOp(dst,n,a)||!readOp(src,n,b)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

            } else {
                dst.reg=true;
                dst.id=0;
                a=readReg(0,n);

                if(!readImm(n==8?4:n,b)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                if(n==8)
                    b=uint64_t(int64_t(int32_t(b)));
            }

            const auto old=s;
            uint64_t result=alu(group,n,a,b);

            if(group!=7 && !writeOp(dst,n,result)) {
                s=old;
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            s.rip=pc;
            ++s.steps;
            continue;
        }

        // Group 1 immediate arithmetic.
        if(op==0x80 || op==0x81 || op==0x83) {

            uint8_t m=0;
            Operand dst;

            if(!fetch(pc,m)||!decodeRM(m,dst)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            unsigned group=(m>>3)&7;
            unsigned n=op==0x80?1:((rex&8)?8:(simdPrefix==0x66?2:4));
            unsigned width=op==0x83?1:(n==8?4:n);

            uint64_t a=0,b=0;

            if(!readImm(width,b)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if(op==0x83)
                b=uint64_t(int64_t(int8_t(b)));
            else if(n==8)
                b=uint64_t(int64_t(int32_t(b)));

            if(!readOp(dst,n,a)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const auto old=s;
            uint64_t result=alu(group,n,a,b);

            if(group!=7 && !writeOp(dst,n,result)) {
                s=old;
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            s.rip=pc;
            ++s.steps;
            continue;
        }

        // TEST register/memory and accumulator.
        if(op==0x84 || op==0x85 ||
           op==0xa8 || op==0xa9) {

            unsigned n=(op&1)?((rex&8)?8:(simdPrefix==0x66?2:4)):1;
            uint64_t a=0,b=0;

            if(op==0x84 || op==0x85) {

                uint8_t m=0;
                Operand rm;

                if(!fetch(pc,m)||!decodeRM(m,rm)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                unsigned r=((m>>3)&7)+((rex&4)?8:0);

                if(!readOp(rm,n,a)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                b=readReg(r,n);

            } else {
                a=readReg(0,n);

                if(!readImm(n==8?4:n,b)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                if(n==8)
                    b=uint64_t(int64_t(int32_t(b)));
            }

            alu(4,n,a,b);

            s.rip=pc;
            ++s.steps;
            continue;
        }


        if((simdPrefix==0 || simdPrefix==0x66) && (op==0x86 || op==0x87)) {
            uint8_t m=0; Operand rm; uint64_t v=0;
            unsigned n=op==0x86?1:(rex&8)?8:simdPrefix==0x66?2:4;
            if(!fetch(pc,m)||!decodeRM(m,rm)||!readOp(rm,n,v)){s.exit=Cpu64Exit::memoryFault;break;}
            unsigned r=((m>>3)&7)+((rex&4)?8:0);
            if(!writeOp(rm,n,readReg(r,n))){s.exit=Cpu64Exit::memoryFault;break;}
            writeReg(r,n,v);s.rip=pc;++s.steps;continue;
        }
        // V42: group 3, all operand widths. Divide faults stop without changing registers.
        if(op==0xf6 || op==0xf7) {
            uint8_t m=0; Operand dst;
            if(!fetch(pc,m)||!decodeRM(m,dst)){s.exit=Cpu64Exit::memoryFault;break;}
            unsigned g=(m>>3)&7,n=op==0xf6?1:(rex&8)?8:simdPrefix==0x66?2:4,bits=n*8;
            uint64_t v=0,imm=0,mask=maskFor(n);
            if(g==1){s.exit=Cpu64Exit::unsupported;break;}
            if(g==0 && !readImm(n==8?4:n,imm)){s.exit=Cpu64Exit::memoryFault;break;}
            if(!readOp(dst,n,v)){s.exit=Cpu64Exit::memoryFault;break;}
            if(g==0){if(n==8)imm=uint64_t(int64_t(int32_t(imm)));alu(4,n,v,imm);}
            else if(g==2||g==3){auto old=s;auto z=g==2?~v:alu(5,n,0,v);if(!writeOp(dst,n,z)){s=old;s.exit=Cpu64Exit::memoryFault;break;}}
            else {
                using U=__uint128_t; using I=__int128_t;
                auto sx=[](U x,unsigned w)->I {U sign=U(1)<<(w-1);return (x&sign)?-I(~x & (sign-1))-1:I(x);};
                U lo=readReg(0,n),hi=n==1?readReg(4,1):readReg(2,n);
                if(n==1)hi=(s.gpr[0]>>8)&255;
                U q=0,r=0;
                if(g==4||g==5){U product=g==4?lo*U(v):U(sx(lo,bits)*sx(v,bits));q=product&mask;r=(product>>bits)&mask;s.cf=s.of=g==4?r!=0:sx(q,bits)!=sx(product & (bits==64?~U(0):(U(1)<<(2*bits))-1),2*bits);}
                else {
                    if(!v){s.exit=Cpu64Exit::unsupported;break;}
                    U dividend=(hi<<bits)|lo;
                    if(g==6){q=dividend/v;r=dividend%v;if(q>mask){s.exit=Cpu64Exit::unsupported;break;}}
                    else {I x=sx(dividend,2*bits),y=sx(v,bits);if(dividend==(U(1)<<(2*bits-1))&&y==-1){s.exit=Cpu64Exit::unsupported;break;}I z=x/y;I lim=I(1)<<(bits-1);if(z < -lim || z>=lim){s.exit=Cpu64Exit::unsupported;break;}q=U(z);r=U(x%y);}
                }
                if(n==1)writeReg(0,2,uint64_t((q&255)|((r&255)<<8)));else {writeReg(0,n,uint64_t(q));writeReg(2,n,uint64_t(r));}
            }
            s.rip=pc;++s.steps;continue;
        }

        // ALIEN_CONTROL_FLOW_V6
        if(op==0xff || op==0xfe) {

            uint8_t m=0;
            Operand dst;

            if(!fetch(pc,m)||!decodeRM(m,dst)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            unsigned group=(m>>3)&7;

            // INC / DEC
            if(group==0 || group==1) {

                unsigned n=op==0xfe?1:
                    ((rex&8)?8:(simdPrefix==0x66?2:4));

                uint64_t value=0;

                if(!readOp(dst,n,value)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const auto old=s;
                bool carry=s.cf;

                uint64_t result=alu(
                    group==0?0:5,n,value,1);

                s.cf=carry;

                if(!writeOp(dst,n,result)) {
                    s=old;
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.rip=pc;
                ++s.steps;
                continue;
            }

            if(op==0xfe ||
               (group!=2 && group!=4 && group!=6)) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            uint64_t target=0;

            if(!readOp(dst,8,target)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            // PUSH r/m64
            if(group==6) {

                if(s.gpr[4]<8) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint64_t rsp=s.gpr[4]-8;
                std::array<uint8_t,8> bytes{};

                for(unsigned i=0;i<8;++i)
                    bytes[i]=uint8_t(target>>(i*8));

                if(memory.write(rsp,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.gpr[4]=rsp;
                s.rip=pc;
                ++s.steps;
                continue;
            }

            // Imported CALL or tail JMP.
            if(imports && imports->contains(target)) {

                uint64_t dest=pc;

                if(group==4) {

                    std::array<uint8_t,8> ret{};

                    if(s.gpr[4]>UINT64_MAX-8 ||
                       memory.read(s.gpr[4],ret)!=
                       GuestMemory64::Fault::none) {
                        s.exit=Cpu64Exit::memoryFault;
                        break;
                    }

                    dest=0;

                    for(unsigned i=0;i<8;++i)
                        dest|=uint64_t(ret[i])<<(i*8);

                    if(memory.check(dest,1,
                       GuestMemory64::Execute)!=
                       GuestMemory64::Fault::none) {
                        s.exit=Cpu64Exit::memoryFault;
                        break;
                    }
                }

                const auto symbol=imports->name(target);
                if(std::getenv("ALIEN_TRACE")) std::fprintf(stderr,"TRACE step=%llu rip=%llx %s rcx=%llx rdx=%llx r8=%llx r9=%llx\n",(unsigned long long)s.steps,(unsigned long long)s.rip,symbol.c_str(),(unsigned long long)s.gpr[1],(unsigned long long)s.gpr[2],(unsigned long long)s.gpr[8],(unsigned long long)s.gpr[9]);
                if(symbol=="nexttowardf" || (target>=ScarlettImports64::StubBase+0x910 && target<ScarlettImports64::StubBase+0xb20)) {
                    // Scalar CRT math, Win64 XMM argument and return ABI.
                    // Host math approximates guest libm; guest FP exceptions are not modeled.
                    float a=0,b=0;double x=0,y=0;
                    std::memcpy(&a,s.xmm[0].data(),4);std::memcpy(&b,s.xmm[1].data(),4);
                    std::memcpy(&x,s.xmm[0].data(),8);std::memcpy(&y,s.xmm[1].data(),8);
                    if(symbol=="acos") {double v=std::acos(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="acosf") {float v=std::acos(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="asin") {double v=std::asin(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="asinf") {float v=std::asin(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="atan") {double v=std::atan(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="atan2") {double v=std::atan2(x,y);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="atan2f") {float v=std::atan2(a,b);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="atanf") {float v=std::atan(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="cbrtf") {float v=std::cbrt(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="ceilf") {float v=std::ceil(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="cos") {double v=std::cos(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="cosf") {float v=std::cos(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="erff") {float v=std::erf(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="exp") {double v=std::exp(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="exp2") {double v=std::exp2(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="exp2f") {float v=std::exp2(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="expf") {float v=std::exp(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="fmod") {double v=std::fmod(x,y);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="fmodf") {float v=std::fmod(a,b);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="log") {double v=std::log(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="log10f") {float v=std::log10(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="log2") {double v=std::log2(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="log2f") {float v=std::log2(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="logf") {float v=std::log(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="pow") {double v=std::pow(x,y);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="powf") {float v=std::pow(a,b);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="remainderf") {float v=std::remainder(a,b);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="sin") {double v=std::sin(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="sinf") {float v=std::sin(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="sinhf") {float v=std::sinh(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="tan") {double v=std::tan(x);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="tanf") {float v=std::tan(a);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="nexttowardf") {float v=std::nexttoward(a,static_cast<long double>(y));std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else if(symbol=="nextafterf") {float v=std::nextafter(a,b);std::memcpy(s.xmm[0].data(),&v,sizeof(v));}
                    else {s.exit=Cpu64Exit::unsupported;break;}
                } else if(symbol=="RtlCaptureContext") {
                    // Windows AMD64 CONTEXT layout. Only integer state is advertised:
                    // segment, x87, MXCSR and full EFLAGS are not modeled yet.
                    std::array<uint8_t,1232> context{};
                    auto put=[&](unsigned off,uint64_t value,unsigned n){
                        for(unsigned i=0;i<n;++i) context[off+i]=uint8_t(value>>(8*i));
                    };
                    put(48,0x00100002,4); // CONTEXT_AMD64 | CONTEXT_INTEGER
                    constexpr unsigned order[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
                    for(unsigned i=0;i<16;++i) put(120+i*8,s.gpr[order[i]],8);
                    put(152,s.gpr[4]+(group==4?8:0),8);
                    put(248,dest,8);
                    put(68,2u|(s.cf?1u:0u)|(s.pf?4u:0u)|(s.zf?64u:0u)|(s.sf?128u:0u)|(s.of?2048u:0u),4);
                    for(unsigned i=0;i<16;++i) for(unsigned j=0;j<16;++j) context[416+i*16+j]=s.xmm[i][j];
                    if(memory.write(s.gpr[1],context)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                } else if(symbol=="_initterm_e" || symbol=="_initterm" || symbol=="_cexit") {
                    const bool exiting=symbol=="_cexit";
                    const auto begin=s.gpr[1], end=s.gpr[2];
                    if(depth>=8 || (!exiting && (end<begin || (end-begin)%8 ||
                       (end-begin)/8>65536))) {
                        s.exit=Cpu64Exit::unsupported; break;
                    }
                    uint64_t result=0;
                    bool failed=false;
                    for(uint64_t at=begin;exiting?imports->hasExitCallback():at<end;at+=8) {
                        std::array<uint8_t,8> bytes{};
                        if(!exiting && memory.read(at,bytes)!=GuestMemory64::Fault::none) {
                            s.exit=Cpu64Exit::memoryFault; failed=true; break;
                        }
                        uint64_t fn=0;
                        for(unsigned i=0;i<8;++i) fn|=uint64_t(bytes[i])<<(8*i);
                        if(exiting) fn=imports->popExitCallback();
                        if(!fn) continue;
                        if(s.steps+1>=budget || s.gpr[4]<80) {
                            s.exit=Cpu64Exit::budget; failed=true; break;
                        }
                        const uint64_t rsp=((s.gpr[4]-64)&~uint64_t(15))-8;
                        const uint64_t callbackReturn=ScarlettImports64::StubBase+0xe00+depth*16;
                        for(unsigned i=0;i<8;++i) bytes[i]=uint8_t(callbackReturn>>(8*i));
                        if(memory.write(rsp,bytes)!=GuestMemory64::Fault::none) {
                            s.exit=Cpu64Exit::memoryFault; failed=true; break;
                        }
                        auto child=executeGuest64(memory,fn,budget-s.steps-1,
                            rsp,imports,gsBase,fsBase,callbackReturn,depth+1,&s);
                        s.steps+=child.steps;
                        if(child.rip!=callbackReturn || child.exit!=Cpu64Exit::budget ||
                           child.gpr[4]!=rsp+8) {
                            child.steps=s.steps;
                            s=child; failed=true; break;
                        }
                        if(symbol=="_initterm_e" && uint32_t(child.gpr[0])) {
                            result=uint32_t(child.gpr[0]); break;
                        }
                    }
                    if(failed) break;
                    if(symbol=="_initterm_e") s.gpr[0]=result;
                } else {
                    uint64_t arg5=UINT64_MAX, arg6=UINT64_MAX;
                    if(symbol=="XMemVirtualAlloc" || symbol=="CreateSemaphoreExW") {
                        std::array<uint8_t,8> b{};
                        if(memory.read(s.gpr[4]+(group==4?40:32),b)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                        arg5=0;for(unsigned j=0;j<8;++j)arg5|=uint64_t(b[j])<<(8*j);
                        if(symbol=="CreateSemaphoreExW") { if(memory.read(s.gpr[4]+(group==4?48:40),b)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;} arg6=0;for(unsigned j=0;j<8;++j)arg6|=uint64_t(b[j])<<(8*j); }
                    }
                    if(!imports->dispatch(target,memory,s.gpr[1],s.gpr[0],s.gpr[2],s.gpr[8],s.gpr[9],arg5,arg6,&s.xmm[0])){s.exit=Cpu64Exit::memoryFault;break;}
                }

                if(group==4)
                    s.gpr[4]+=8;

                s.rip=dest;
                ++s.steps;
                continue;
            }

            // Ordinary guest CALL / JMP.
            if(memory.check(target,1,
               GuestMemory64::Execute)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if(group==2) {

                if(s.gpr[4]<8) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint64_t rsp=s.gpr[4]-8;
                std::array<uint8_t,8> ret{};

                for(unsigned i=0;i<8;++i)
                    ret[i]=uint8_t(pc>>(i*8));

                if(memory.write(rsp,ret)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.gpr[4]=rsp;
            }

            s.rip=target;
            ++s.steps;
            continue;
        }

        if(op==0x63 && (rex&8)) {
            uint8_t m=0; Operand rm{}; uint64_t v=0;
            if(!fetch(pc,m)||!decodeRM(m,rm)||!readOp(rm,4,v)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            if(v&0x80000000ull)v|=0xffffffff00000000ull;
            writeReg(((m>>3)&7)|((rex&4)?8:0),8,v);
            s.rip=pc;++s.steps;continue;
        }
        // V37 accumulator sign extension and register exchange.
        if((simdPrefix==0 || simdPrefix==0x66) &&
           (op==0x98 || op==0x99 || (op>=0x90 && op<=0x97))) {
            unsigned n=(rex&8)?8:simdPrefix==0x66?2:4;
            if(op==0x98) {
                uint64_t v=readReg(0,n/2), sign=uint64_t(1)<<(n*4-1);
                if(v&sign)v|=~maskFor(n/2);
                writeReg(0,n,v);
            } else if(op==0x99) {
                writeReg(2,n,(readReg(0,n)&(uint64_t(1)<<(n*8-1)))?UINT64_MAX:0);
            } else {
                unsigned r=(op&7)+((rex&1)?8:0);
                if(r!=0){auto a=readReg(0,n),b=readReg(r,n);writeReg(0,n,b);writeReg(r,n,a);}
            }
            s.rip=pc;++s.steps;continue;
        }
        if(!simdPrefix && (op==0xf5 || op==0xf8 || op==0xf9)) {
            s.cf=op==0xf5?!s.cf:op==0xf9;
            s.rip=pc;++s.steps;continue;
        }
        // V31 shift group, all integer widths.
        if(op==0xc0 || op==0xc1 || (op>=0xd0 && op<=0xd3)) {
            unsigned n=(op==0xc0||op==0xd0||op==0xd2)?1:((rex&8)?8:(simdPrefix==0x66?2:4));
            unsigned bits=n*8; uint8_t m=0; Operand rm{}; uint64_t count=1,v=0;
            if(!fetch(pc,m)||!decodeRM(m,rm)) {s.exit=Cpu64Exit::memoryFault;break;}
            unsigned g=(m>>3)&7;
            if(op==0xc0||op==0xc1){if(!readImm(1,count)){s.exit=Cpu64Exit::memoryFault;break;}}
            else if(op==0xd2||op==0xd3)count=s.gpr[1]&255;
            count&=bits==64?63:31;
            if(!readOp(rm,n,v)){s.exit=Cpu64Exit::memoryFault;break;}
            if(g<4){
                const unsigned effective=unsigned(count)%(bits+(g>=2?1:0));
                uint64_t r=v; bool cf=s.cf;
                const uint64_t sign=uint64_t(1)<<(bits-1);
                for(unsigned i=0;i<effective;++i){
                    if(g==0||g==2){const bool out=(r&sign)!=0;r=((r<<1)&maskFor(n))|uint64_t(g==0?out:cf);cf=out;}
                    else {const bool out=(r&1)!=0;r=(r>>1)|((g==1?out:cf)?sign:0);cf=out;}
                }
                if(count && (g<2 || effective)){
                    if(!writeOp(rm,n,r)){s.exit=Cpu64Exit::memoryFault;break;}
                    if(g==0)cf=(r&1)!=0;
                    if(g==1)cf=(r&sign)!=0;
                    s.cf=cf;
                    if(count==1)s.of=(g==0||g==2)?((r&sign)!=0)!=cf:((r&sign)!=0)!=((r&(sign>>1))!=0);
                }
                s.rip=pc;++s.steps;continue;
            }
            if(count){uint64_t r=v;bool cf=s.cf;const uint64_t sign=uint64_t(1)<<(bits-1);
                for(unsigned i=0;i<count;++i){if(g==4||g==6){cf=(r&sign)!=0;r=(r<<1)&maskFor(n);}else{cf=r&1;r=(r>>1)|(g==7?(r&sign):0);}}
                if(!writeOp(rm,n,r)){s.exit=Cpu64Exit::memoryFault;break;}
                s.cf=cf;s.zf=r==0;s.sf=(r&sign)!=0;s.pf=(std::popcount(unsigned(r&255))%2)==0;
                if(count==1)s.of=(g==4||g==6)?(s.sf!=s.cf):(g==5?(v&sign)!=0:false);
            }
            s.rip=pc;++s.steps;continue;
        }
        // V29 signed multiply, immediate forms.
        if(op==0x69 || op==0x6b) {
            unsigned n=(rex&8)?8:(simdPrefix==0x66?2:4);
            unsigned k=op==0x6b?1:(n==8?4:n);
            uint8_t m=0; Operand rm{}; uint64_t a=0,b=0;
            if(!fetch(pc,m)||!decodeRM(m,rm)||!readImm(k,b)||!readOp(rm,n,a)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            auto sx=[](uint64_t v,unsigned bytes)->__int128 {
                __int128 x=v; if(v&(uint64_t(1)<<(bytes*8-1)))x-=(__int128(1)<<(bytes*8));return x;
            };
            auto product=sx(a,n)*sx(b,k);
            uint64_t result=uint64_t(product)&maskFor(n);
            s.cf=s.of=product!=sx(result,n);
            writeReg(((m>>3)&7)|((rex&4)?8:0),n,result);
            s.rip=pc;++s.steps;continue;
        }
        // All immediate MOV register encodings.
        if(op>=0xb0 && op<=0xbf) {
            unsigned n=op<0xb8?1:((rex&8)?8:(simdPrefix==0x66?2:4));
            unsigned r=(op&7)+((rex&1)?8:0);
            uint64_t v=0;
            if(!readImm(n,v)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            writeReg(r,n,v);
            s.rip=pc;++s.steps;continue;
        }

        // General MOV and LEA with ModRM/SIB.
        if((op>=0x88 && op<=0x8b) || op==0x8d ||
            op==0xc6 || op==0xc7) {

            uint8_t m=0;
            Operand rm;
            if(!fetch(pc,m)||!decodeRM(m,rm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            unsigned r=((m>>3)&7)+((rex&4)?8:0);
            unsigned n=(rex&8)?8:(simdPrefix==0x66?2:4);

            if(op==0x88 || op==0x8a || op==0xc6)
                n=1;

            uint64_t v=0;
            bool ok=true;

            if(op==0x8d) {
                if(rm.reg) {
                    s.exit=Cpu64Exit::unsupported;break;
                }
                writeReg(r,n,rm.addr+(rm.relative?pc:0));
            } else if(op==0xc6 || op==0xc7) {
                if(((m>>3)&7)!=0) {
                    s.exit=Cpu64Exit::unsupported;break;
                }
                if(!readImm(n==8?4:n,v)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                if(n==8) v=uint64_t(int64_t(int32_t(v)));
                ok=writeOp(rm,n,v);
            } else if(op==0x88 || op==0x89) {
                ok=writeOp(rm,n,readReg(r,n));
            } else {
                ok=readOp(rm,n,v);
                if(ok) writeReg(r,n,v);
            }

            if(!ok) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            s.rip=pc;++s.steps;continue;
        }

        // All 16 short conditional branches and JMP.
        if((op>=0x70 && op<=0x7f)||op==0xeb) {
            uint8_t d=0;
            if(!fetch(pc,d)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            uint64_t dest=pc;
            if(op==0xeb || condition(op&15))
                dest+=uint64_t(int64_t(int8_t(d)));

            if(memory.check(dest,1,GuestMemory64::Execute)
                !=GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            s.rip=dest;++s.steps;continue;
        }

        // Extended conditional instructions.
        if(op==0x0f) {
            uint64_t saved=pc;
            uint8_t ext=0;
            if(!fetch(pc,ext)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }


            if(locked && ext!=0xb0 && ext!=0xb1) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            // CMPXCHG r/m8, r8
            // CMPXCHG r/m32/64, r32/64
            if(ext==0xb0 || ext==0xb1) {

                uint8_t m=0;
                Operand dst;

                if(!fetch(pc,m)||!decodeRM(m,dst)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                if(locked && dst.reg) {
                    s.exit=Cpu64Exit::unsupported;
                    break;
                }

                unsigned n=ext==0xb0?1:
                    ((rex&8)?8:4);

                unsigned src=
                    ((m>>3)&7)+((rex&4)?8:0);

                uint64_t expected=readReg(0,n);
                uint64_t replacement=readReg(src,n);
                uint64_t actual=0;

                if(!readOp(dst,n,actual)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const auto old=s;

                alu(7,n,expected,actual);

                uint64_t value=s.zf?
                    replacement:actual;

                if(!writeOp(dst,n,value)) {
                    s=old;
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                if(!s.zf)
                    writeReg(0,n,actual);

                s.rip=pc;
                ++s.steps;
                continue;
            }

            if(ext>=0x80 && ext<=0x8f) {
                uint32_t d=0;
                if(!imm32(d)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                uint64_t dest=pc;
                if(condition(ext&15))
                    dest+=uint64_t(int64_t(int32_t(d)));

                if(memory.check(dest,1,GuestMemory64::Execute)
                    !=GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                s.rip=dest;++s.steps;continue;
            }

            if((ext>=0x40 && ext<=0x4f) ||
               (ext>=0x90 && ext<=0x9f) ||
               ext==0xb6 || ext==0xb7 ||
               ext==0xbe || ext==0xbf) {

                uint8_t m=0;
                Operand rm;
                if(!fetch(pc,m)||!decodeRM(m,rm)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                unsigned r=((m>>3)&7)+((rex&4)?8:0);
                unsigned n=(rex&8)?8:4;
                uint64_t v=0;
                bool ok=true;

                if(ext>=0x90 && ext<=0x9f) {
                    ok=writeOp(rm,1,condition(ext&15)?1:0);
                } else if(ext>=0x40 && ext<=0x4f) {
                    ok=readOp(rm,n,v);
                    if(ok && condition(ext&15))
                        writeReg(r,n,v);
                } else {
                    unsigned src=(ext&1)?2:1;
                    ok=readOp(rm,src,v);
                    if(ext==0xbe)
                        v=uint64_t(int64_t(int8_t(v)));
                    if(ext==0xbf)
                        v=uint64_t(int64_t(int16_t(v)));
                    if(ok) writeReg(r,n,v);
                }

                if(!ok) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                s.rip=pc;++s.steps;continue;
            }

            // Preserve existing CPUID, BT and other handlers.
            pc=saved;
        }

        // TEST r/m32, r32 or TEST r/m64, r64.
        // Updates ZF without modifying either operand.
        if(op==0x85) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xc0)!=0xc0) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            const unsigned dst=
                (modrm&7)+((rex&1)?8:0);
            const unsigned src=
                ((modrm>>3)&7)+((rex&4)?8:0);

            if(rex&8) {
                s.zf=((s.gpr[dst]&s.gpr[src])==0);
            } else {
                const uint32_t result=
                    static_cast<uint32_t>(s.gpr[dst]) &
                    static_cast<uint32_t>(s.gpr[src]);
                s.zf=(result==0);
            }

            s.rip=pc;
            ++s.steps;
            continue;
        }


        // RIP-relative MOV byte store: 88 /r, mod=00, r/m=101.
        if(op==0x88) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xc7)!=0x05) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            uint32_t raw=0;
            if(!imm32(raw)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned src=
                ((modrm>>3)&7)+((rex&4)?8:0);

            // Without REX, register codes 4-7 refer to
            // AH/CH/DH/BH rather than SPL/BPL/SIL/DIL.
            const bool hasRex=(rex!=0);
            uint8_t value=0;

            if(!hasRex && src>=4 && src<=7)
                value=uint8_t(s.gpr[src-4]>>8);
            else
                value=uint8_t(s.gpr[src]);

            const int64_t disp=static_cast<int32_t>(raw);
            const uint64_t addr=
                pc+static_cast<uint64_t>(disp);

            const std::array<uint8_t,1> bytes{value};

            if(memory.write(addr,bytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            s.rip=pc;
            ++s.steps;
            continue;
        }


        // Group 1 opcode 81 /6:
        // XOR r32, imm32 (register form).
        if(op==0x81 && !(rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned mode=modrm>>6;
            const unsigned group=(modrm>>3)&7;

            if(mode==3 && group==6) {
                uint32_t imm=0;
                if(!imm32(imm)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned dst=
                    (modrm&7)+((rex&1)?8:0);

                const uint32_t result=
                    static_cast<uint32_t>(s.gpr[dst]) ^ imm;

                s.gpr[dst]=result;
                s.zf=(result==0);

                s.rip=pc;
                ++s.steps;
                continue;
            }

            s.exit=Cpu64Exit::unsupported;
            break;
        }


        // LEA r32, [base + disp8].
        // Address calculation only; no memory access.
        if(op==0x8d && !(rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned mode=modrm>>6;
            const unsigned rm=modrm&7;

            if(mode==1 && rm!=4) {
                uint8_t rawDisp=0;
                if(!fetch(pc,rawDisp)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned dst=
                    ((modrm>>3)&7)+((rex&4)?8:0);
                const unsigned base=
                    rm+((rex&1)?8:0);

                const int64_t disp=
                    static_cast<int8_t>(rawDisp);

                const uint64_t address=
                    s.gpr[base]+static_cast<uint64_t>(disp);

                s.gpr[dst]=static_cast<uint32_t>(address);
                s.rip=pc;
                ++s.steps;
                continue;
            }

            s.exit=Cpu64Exit::unsupported;
            break;
        }


        // OR r32, r/m32: register form.
        if(op==0x0b && !(rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xc0)!=0xc0) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            const unsigned dst=
                ((modrm>>3)&7)+((rex&4)?8:0);
            const unsigned src=
                (modrm&7)+((rex&1)?8:0);

            const uint32_t result=
                static_cast<uint32_t>(s.gpr[dst]) |
                static_cast<uint32_t>(s.gpr[src]);

            s.gpr[dst]=result;
            s.zf=(result==0);

            s.rip=pc;
            ++s.steps;
            continue;
        }


        // MOV [RSP+disp8], r32: SIB register store.
        if(op==0x89 && !(rex&8)) {
            const uint64_t modrmStart=pc;
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned mode=modrm>>6;
            const unsigned rm=modrm&7;

            if((mode==0 || mode==1) && rm==4) {
                uint8_t sib=0;
                if(!fetch(pc,sib)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                if(sib!=0x24 || (rex&1)) {
                    s.exit=Cpu64Exit::unsupported;
                    break;
                }

                int64_t displacement=0;

                if(mode==1) {
                    uint8_t disp=0;
                    if(!fetch(pc,disp)) {
                        s.exit=Cpu64Exit::memoryFault;
                        break;
                    }
                    displacement=static_cast<int8_t>(disp);
                }

                const unsigned src=
                    ((modrm>>3)&7)+((rex&4)?8:0);

                const uint32_t value=
                    static_cast<uint32_t>(s.gpr[src]);

                const uint64_t addr=s.gpr[4]+
                    static_cast<uint64_t>(displacement);

                std::array<uint8_t,4> bytes{};
                for(unsigned i=0;i<4;++i)
                    bytes[i]=uint8_t(value>>(8*i));

                if(memory.write(addr,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.rip=pc;
                ++s.steps;
                continue;
            }

            // Restore the decoder position so the later
            // RIP-relative MOV handler can read ModR/M.
            pc=modrmStart;
        }

        
        // OR qword ptr [RIP+disp32], sign-extended imm8.
        if(op==0x83 && (rex&8)) {
            uint8_t modrm=0;

            // Peek without advancing the actual decoder.
            uint64_t probe=pc;
            if(!fetch(probe,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if(modrm==0x0d) {
                pc=probe;

                uint32_t raw=0;
                if(!imm32(raw)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint8_t imm=0;
                if(!fetch(pc,imm)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const uint64_t addr=
                    pc+static_cast<uint64_t>(
                        static_cast<int64_t>(
                            static_cast<int32_t>(raw)));

                std::array<uint8_t,8> bytes{};
                if(memory.read(addr,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint64_t value=0;
                for(unsigned i=0;i<8;++i)
                    value|=uint64_t(bytes[i])<<(8*i);

                const uint64_t mask=
                    static_cast<uint64_t>(
                        static_cast<int64_t>(
                            static_cast<int8_t>(imm)));

                value|=mask;

                for(unsigned i=0;i<8;++i)
                    bytes[i]=uint8_t(value>>(8*i));

                if(memory.write(addr,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.zf=(value==0);
                s.rip=pc;
                ++s.steps;
                continue;
            }
        }


        // AND EAX, imm32 (opcode 25).
        // A 32-bit result zero-extends into RAX.
        if(op==0x25 && !(rex&8)) {
            uint32_t imm=0;
            if(!imm32(imm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const uint32_t result=
                static_cast<uint32_t>(s.gpr[0]) & imm;

            s.gpr[0]=result;
            s.zf=(result==0);
            s.rip=pc;
            ++s.steps;
            continue;
        }


        // CMP EAX, imm32.
        // Compares 32-bit values without modifying EAX.
        if(op==0x3d && !(rex&8)) {
            uint32_t imm=0;
            if(!imm32(imm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const uint32_t eax=
                static_cast<uint32_t>(s.gpr[0]);

            const uint32_t result=eax-imm;

            s.zf=(result==0);
            s.rip=pc;
            ++s.steps;
            continue;
        }


        // JE/JZ rel8: jump when zero flag is set.
        if(op==0x74) {
            uint8_t raw=0;
            if(!fetch(pc,raw)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const int64_t disp=
                static_cast<int8_t>(raw);

            const uint64_t dest=s.zf
                ? pc+static_cast<uint64_t>(disp)
                : pc;

            if(memory.check(dest,1,
                GuestMemory64::Execute)!=
                GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            s.rip=dest;
            ++s.steps;
            continue;
        }


        // ADD EAX, imm32: 32-bit addition, zero-extended into RAX.
        if(op==0x05 && !(rex&8)) {
            uint32_t imm=0;
            if(!imm32(imm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const uint32_t a=
                static_cast<uint32_t>(s.gpr[0]);
            const uint32_t result=a+imm;

            s.cf=(result<a);
            s.of=((~(a^imm)&(a^result)&0x80000000u)!=0);
            s.zf=(result==0);
            s.sf=(result>>31)!=0;

            uint8_t low=static_cast<uint8_t>(result);
            low^=low>>4;
            low^=low>>2;
            low^=low>>1;
            s.pf=((low&1)==0);

            s.gpr[0]=result;
            s.rip=pc;
            ++s.steps;
            continue;
        }


        // CMP r32, sign-extended imm8: opcode 83 /7.
        if(op==0x83 && !(rex&8)) {
            uint64_t probe=pc;
            uint8_t modrm=0;

            if(!fetch(probe,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xf8)==0xf8) {
                pc=probe;

                uint8_t raw=0;
                if(!fetch(pc,raw)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned reg=
                    (modrm&7)+((rex&1)?8:0);

                const uint32_t a=
                    static_cast<uint32_t>(s.gpr[reg]);
                const uint32_t b=
                    static_cast<uint32_t>(
                        static_cast<int32_t>(
                            static_cast<int8_t>(raw)));
                const uint32_t result=a-b;

                s.cf=(a<b);
                s.zf=(result==0);
                s.sf=(result>>31)!=0;
                s.of=(((a^b)&(a^result)&0x80000000u)!=0);

                uint8_t low=static_cast<uint8_t>(result);
                low^=low>>4;
                low^=low>>2;
                low^=low>>1;
                s.pf=((low&1)==0);

                s.rip=pc;
                ++s.steps;
                continue;
            }
        }

        // JA rel8: unsigned above (CF=0 and ZF=0).
        if(op==0x77) {
            uint8_t raw=0;
            if(!fetch(pc,raw)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const uint64_t dest=(!s.cf && !s.zf)
                ? pc+static_cast<uint64_t>(
                    static_cast<int64_t>(
                        static_cast<int8_t>(raw)))
                : pc;

            if(memory.check(dest,1,
                GuestMemory64::Execute)!=
                GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            s.rip=dest;
            ++s.steps;
            continue;
        }


        // MOV r32, [RIP+disp32] (8B /r).
        // A 32-bit register write zero-extends into 64 bits.
        if(op==0x8b && !(rex&8)) {
            uint64_t probe=pc;
            uint8_t modrm=0;

            if(!fetch(probe,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xc7)==0x05) {
                pc=probe;

                uint32_t raw=0;
                if(!imm32(raw)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned dst=
                    ((modrm>>3)&7)+((rex&4)?8:0);

                const uint64_t addr=
                    pc+static_cast<uint64_t>(
                        static_cast<int64_t>(
                            static_cast<int32_t>(raw)));

                std::array<uint8_t,4> bytes{};
                if(memory.read(addr,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint32_t value=0;
                for(unsigned i=0;i<4;++i)
                    value|=uint32_t(bytes[i])<<(8*i);

                s.gpr[dst]=value;
                s.rip=pc;
                ++s.steps;
                continue;
            }
        }

// Group 1 opcode 83: sign-extended imm8 operations.
        if(op==0x83 && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const unsigned mode=modrm>>6;
            const unsigned group=(modrm>>3)&7;
            const unsigned rm=modrm&7;

            // ADD/SUB RSP, imm8.
            if(mode==3 && rm==4 &&
               !(rex&1) && (group==0 || group==5)) {
                uint8_t imm=0;
                if(!fetch(pc,imm)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                const uint64_t amount=static_cast<uint64_t>(
                    static_cast<int64_t>(static_cast<int8_t>(imm)));

                if(group==5) s.gpr[4]-=amount;
                else s.gpr[4]+=amount;

                s.rip=pc;++s.steps;continue;
            }

            // AND qword ptr [base+disp8], imm8.
            if(mode==1 && group==4 && rm!=4) {
                uint8_t disp8=0,imm8=0;
                if(!fetch(pc,disp8) || !fetch(pc,imm8)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                const unsigned base=rm+((rex&1)?8:0);
                const uint64_t addr=s.gpr[base]+
                    static_cast<uint64_t>(
                        static_cast<int64_t>(
                            static_cast<int8_t>(disp8)));

                std::array<uint8_t,8> bytes{};
                if(memory.read(addr,bytes)!=GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                uint64_t value=0;
                for(unsigned i=0;i<8;++i)
                    value|=uint64_t(bytes[i])<<(8*i);

                const uint64_t mask=static_cast<uint64_t>(
                    static_cast<int64_t>(
                        static_cast<int8_t>(imm8)));
                value &= mask;

                for(unsigned i=0;i<8;++i)
                    bytes[i]=uint8_t(value>>(8*i));

                if(memory.write(addr,bytes)!=GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                s.zf=(value==0);
                s.rip=pc;++s.steps;continue;
            }

            s.exit=Cpu64Exit::unsupported;break;
        }

        // LEA r64, [base + disp8], register destination.
        if(op==0x8d && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const unsigned mode=modrm>>6;
            const unsigned rm=modrm&7;
            const unsigned dst=((modrm>>3)&7)+((rex&4)?8:0);

            // First supported form: [base + signed disp8].
            // SIB, RIP-relative, and other forms remain unsupported.
            if(mode!=1 || rm==4) {
                s.exit=Cpu64Exit::unsupported;break;
            }

            uint8_t rawDisp=0;
            if(!fetch(pc,rawDisp)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const unsigned base=rm+((rex&1)?8:0);
            const int64_t disp=static_cast<int8_t>(rawDisp);

            s.gpr[dst]=s.gpr[base]+
                static_cast<uint64_t>(disp);

            s.rip=pc;
            ++s.steps;
            continue;
        }


        // CALL r/m64: RIP-relative indirect form (FF /2).

        // MOV r64, [RBP/R13 + signed disp8].
        // Example: 48 8B 45 18 = MOV RAX, [RBP+0x18].
        // SHL r64, imm8: C1 /4, register operand.
        if(op==0xc1 && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            // Only ModRM /4 with register addressing.
            if((modrm&0xf8)!=0xe0) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            uint8_t count=0;
            if(!fetch(pc,count)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned reg=
                (modrm&7)+((rex&1)?8:0);

            const unsigned shift=count&63;

            if(shift!=0) {
                const uint64_t value=s.gpr[reg];
                s.gpr[reg]=value<<shift;
                s.zf=(s.gpr[reg]==0);
            }

            s.rip=pc;
            ++s.steps;
            continue;
        }

        if(op==0xff) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            // FF 15 disp32 = CALL qword ptr [RIP+disp32].
            if(modrm!=0x15) {
                s.exit=Cpu64Exit::unsupported;break;
            }

            uint32_t rawDisp=0;
            if(!imm32(rawDisp)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const uint64_t pointerAddress=
                pc+static_cast<uint64_t>(
                    static_cast<int64_t>(
                        static_cast<int32_t>(rawDisp)));

            std::array<uint8_t,8> targetBytes{};
            if(memory.read(pointerAddress,targetBytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            uint64_t target=0;
            for(unsigned i=0;i<8;++i)
                target|=uint64_t(targetBytes[i])<<(8*i);

            // Registered guest import: perform the API operation
            // without executing a host function pointer.
            if(imports && imports->contains(target)) {
                uint64_t arg5=UINT64_MAX, arg6=UINT64_MAX;
                if(imports->name(target)=="XMemVirtualAlloc" || imports->name(target)=="CreateSemaphoreExW") {
                    std::array<uint8_t,8> b{};
                    if(memory.read(s.gpr[4]+32,b)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;}
                    arg5=0;for(unsigned j=0;j<8;++j)arg5|=uint64_t(b[j])<<(8*j);
                    if(imports->name(target)=="CreateSemaphoreExW") { if(memory.read(s.gpr[4]+40,b)!=GuestMemory64::Fault::none){s.exit=Cpu64Exit::memoryFault;break;} arg6=0;for(unsigned j=0;j<8;++j)arg6|=uint64_t(b[j])<<(8*j); }
                }
                if(!imports->dispatch(target,memory,s.gpr[1],s.gpr[0],s.gpr[2],s.gpr[8],s.gpr[9],arg5,arg6,&s.xmm[0])) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }
                // Microsoft x64 ABI: RCX is the first argument.
                // The call returns to the instruction after FF 15.
                s.rip=pc;
                ++s.steps;
                continue;
            }

            if(memory.check(target,1,GuestMemory64::Execute)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            if(s.gpr[4]<8) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const uint64_t newRsp=s.gpr[4]-8;
            std::array<uint8_t,8> returnBytes{};
            for(unsigned i=0;i<8;++i)
                returnBytes[i]=uint8_t(pc>>(8*i));

            if(memory.write(newRsp,returnBytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            s.gpr[4]=newRsp;
            s.rip=target;
            ++s.steps;
            continue;
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


        // XOR r64, r/m64 (REX.W):
        // register form and [RBP/R13 + signed disp8].
        if(op==0x33) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned dst=
                ((modrm>>3)&7)+((rex&4)?8:0);
            const unsigned mode=modrm>>6;
            const unsigned rm=modrm&7;

            uint64_t operand=0;

            if(mode==3) {
                const unsigned src=rm+((rex&1)?8:0);
                operand=s.gpr[src];
            } else if(mode==1 && rm==5) {
                uint8_t rawDisp=0;
                if(!fetch(pc,rawDisp)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned base=5+((rex&1)?8:0);
                const int64_t disp=
                    static_cast<int8_t>(rawDisp);

                const uint64_t address=
                    s.gpr[base]+static_cast<uint64_t>(disp);

                std::array<uint8_t,8> bytes{};
                if(memory.read(address,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                for(unsigned i=0;i<8;++i)
                    operand|=uint64_t(bytes[i])<<(8*i);
            } else {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            if(rex&8) {
                s.gpr[dst]^=operand;
            } else {
                s.gpr[dst]=static_cast<uint32_t>(
                    s.gpr[dst]^operand);
            }
            s.zf=(s.gpr[dst]==0);
            s.rip=pc;
            ++s.steps;
            continue;
        }


        // AND r64, r/m64: register form.
        if(op==0x23 && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xc0)!=0xc0) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            const unsigned dst=
                ((modrm>>3)&7)+((rex&4)?8:0);

            const unsigned src=
                (modrm&7)+((rex&1)?8:0);

            s.gpr[dst]&=s.gpr[src];
            s.zf=(s.gpr[dst]==0);

            s.rip=pc;
            ++s.steps;
            continue;
        }


        // NOT r64: F7 /2, register operand only.
        if(op==0xf7 && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xf8)!=0xd0) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            const unsigned reg=
                (modrm&7)+((rex&1)?8:0);

            s.gpr[reg]=~s.gpr[reg];

            // NOT does not modify flags.
            s.rip=pc;
            ++s.steps;
            continue;
        }

        // MOV r/m64, r64: RSP/SIB and RBP/R13 disp8 forms.

        // XOR r/m64, r64: [RBP/R13 + disp8].
        if(op==0x31 && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            if((modrm&0xc7)!=0x45) {
                s.exit=Cpu64Exit::unsupported;
                break;
            }

            uint8_t rawDisp=0;
            if(!fetch(pc,rawDisp)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned src=
                ((modrm>>3)&7)+((rex&4)?8:0);
            const unsigned base=5+((rex&1)?8:0);

            const int64_t disp=
                static_cast<int8_t>(rawDisp);

            const uint64_t addr=
                s.gpr[base]+static_cast<uint64_t>(disp);

            std::array<uint8_t,8> bytes{};
            if(memory.read(addr,bytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            uint64_t value=0;
            for(unsigned i=0;i<8;++i)
                value|=uint64_t(bytes[i])<<(8*i);

            value ^= s.gpr[src];

            for(unsigned i=0;i<8;++i)
                bytes[i]=uint8_t(value>>(8*i));

            if(memory.write(addr,bytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            s.zf=(value==0);
            s.rip=pc;
            ++s.steps;
            continue;
        }

        if(op==0x89 && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            // RIP-relative MOV store: 48 89 05 disp32.
            if((modrm&0xc7)==0x05) {
                uint32_t raw=0;
                if(!imm32(raw)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned src=
                    ((modrm>>3)&7)+((rex&4)?8:0);

                const uint64_t addr=
                    pc+static_cast<uint64_t>(
                        static_cast<int64_t>(
                            static_cast<int32_t>(raw)));

                std::array<uint8_t,8> bytes{};
                for(unsigned i=0;i<8;++i)
                    bytes[i]=uint8_t(s.gpr[src]>>(8*i));

                if(memory.write(addr,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.rip=pc;
                ++s.steps;
                continue;
            }

            const unsigned mode=modrm>>6;
            const unsigned rm=modrm&7;
            const unsigned src=((modrm>>3)&7)+((rex&4)?8:0);

            if(mode==1 && (rm==4 || rm==5)) {
                unsigned base=0;

                if(rm==4) {
                    uint8_t sib=0;
                    if(!fetch(pc,sib)) {
                        s.exit=Cpu64Exit::memoryFault;break;
                    }
                    // Only base RSP/R12, no index.
                    if(sib!=0x24) {
                        s.exit=Cpu64Exit::unsupported;break;
                    }
                    base=4+((rex&1)?8:0);
                } else {
                    base=5+((rex&1)?8:0);
                }

                uint8_t rawDisp=0;
                if(!fetch(pc,rawDisp)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                const int64_t disp=static_cast<int8_t>(rawDisp);
                const uint64_t address=
                    s.gpr[base]+static_cast<uint64_t>(disp);

                std::array<uint8_t,8> bytes{};
                for(unsigned i=0;i<8;++i)
                    bytes[i]=uint8_t(s.gpr[src]>>(8*i));

                if(memory.write(address,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                s.rip=pc;
                ++s.steps;
                continue;
            }

            s.exit=Cpu64Exit::unsupported;
            break;
        }


        // POP r64: 58-5F, including REX.B.
        if(op>=0x58 && op<=0x5f) {
            const unsigned reg=
                (op-0x58)+((rex&1)?8:0);

            std::array<uint8_t,8> bytes{};
            if(memory.read(s.gpr[4],bytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            uint64_t value=0;
            for(unsigned i=0;i<8;++i)
                value|=uint64_t(bytes[i])<<(i*8);

            const uint64_t nextRsp=s.gpr[4]+8;
            s.gpr[reg]=value;
            s.gpr[4]=nextRsp;

            s.rip=pc;
            ++s.steps;
            continue;
        }

        // PUSH r64, including REX.B extended registers.
        if(op>=0x50 && op<=0x57) {
            const unsigned reg=(op-0x50)+((rex&1)?8:0);
            if(s.gpr[4]<8) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            const uint64_t newRsp=s.gpr[4]-8;
            const uint64_t value=s.gpr[reg];
            std::array<uint8_t,8> bytes{};
            for(unsigned i=0;i<8;++i)
                bytes[i]=uint8_t(value>>(i*8));
            if(memory.write(newRsp,bytes)!=GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            s.gpr[4]=newRsp;
            s.rip=pc;++s.steps;continue;
        }


        // MOV r64, r/m64: register and RIP-relative memory forms.

        // MOV r32, r/m32: register-to-register form.
        // Writing EAX or another 32-bit GPR clears its upper 32 bits.
        // MOV r32, r/m32: register and RBP/R13+disp8.
        // All 32-bit destination writes zero-extend to 64 bits.
        if(op==0x8b && !(rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            const unsigned mode=modrm>>6;
            const unsigned rm=modrm&7;
            const unsigned dst=
                ((modrm>>3)&7)+((rex&4)?8:0);

            if(mode==3) {
                const unsigned src=rm+((rex&1)?8:0);
                s.gpr[dst]=static_cast<uint32_t>(s.gpr[src]);
                s.rip=pc;
                ++s.steps;
                continue;
            }

            if(mode==1 && rm==5) {
                uint8_t rawDisp=0;
                if(!fetch(pc,rawDisp)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned base=5+((rex&1)?8:0);
                const int64_t disp=
                    static_cast<int8_t>(rawDisp);

                const uint64_t address=
                    s.gpr[base]+static_cast<uint64_t>(disp);

                std::array<uint8_t,4> bytes{};
                if(memory.read(address,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint32_t value=0;
                for(unsigned i=0;i<4;++i)
                    value|=uint32_t(bytes[i])<<(8*i);

                s.gpr[dst]=value;
                s.rip=pc;
                ++s.steps;
                continue;
            }

            s.exit=Cpu64Exit::unsupported;
            break;
        }

        if(op==0x8b && (rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const unsigned dst=((modrm>>3)&7)+((rex&4)?8:0);
            const unsigned mode=modrm>>6;
            const unsigned rm=modrm&7;


            // RSP-relative MOV load: 48 8B 5C 24 48.
            if(mode==1 && rm==4) {
                uint8_t sib=0, rawDisp=0;

                if(!fetch(pc,sib) || !fetch(pc,rawDisp)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                // No index, RSP/R12 base.
                if((sib&0x38)!=0x20 || (sib&7)!=4) {
                    s.exit=Cpu64Exit::unsupported;
                    break;
                }

                const unsigned base=4+((rex&1)?8:0);
                const unsigned scale=(sib>>6)&3;
                (void)scale;

                const int64_t disp=
                    static_cast<int8_t>(rawDisp);

                const uint64_t addr=
                    s.gpr[base]+static_cast<uint64_t>(disp);

                std::array<uint8_t,8> bytes{};

                if(memory.read(addr,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint64_t value=0;
                for(unsigned i=0;i<8;++i)
                    value|=uint64_t(bytes[i])<<(8*i);

                s.gpr[dst]=value;
                s.rip=pc;
                ++s.steps;
                continue;
            }

            if(mode==3) {
                const unsigned src=rm+((rex&1)?8:0);
                s.gpr[dst]=s.gpr[src];
                s.rip=pc;++s.steps;continue;
            }

            // mod=00, r/m=101: RIP + signed displacement32.
            if(mode==0 && rm==5) {
                uint32_t raw=0;
                if(!imm32(raw)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                const int64_t disp=static_cast<int32_t>(raw);
                const uint64_t address=
                    pc+static_cast<uint64_t>(disp);

                std::array<uint8_t,8> bytes{};
                if(memory.read(address,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }

                uint64_t value=0;
                for(unsigned i=0;i<8;++i)
                    value|=uint64_t(bytes[i])<<(i*8);

                s.gpr[dst]=value;
                s.rip=pc;++s.steps;continue;
            }

            // mod=01, r/m=101: [RBP/R13 + signed disp8].
            if(mode==1 && rm==5) {
                uint8_t rawDisp=0;
                if(!fetch(pc,rawDisp)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned base=5+((rex&1)?8:0);
                const int64_t disp=static_cast<int8_t>(rawDisp);
                const uint64_t address=
                    s.gpr[base]+static_cast<uint64_t>(disp);

                std::array<uint8_t,8> bytes{};
                if(memory.read(address,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint64_t value=0;
                for(unsigned i=0;i<8;++i)
                    value|=uint64_t(bytes[i])<<(i*8);

                s.gpr[dst]=value;
                s.rip=pc;
                ++s.steps;
                continue;
            }

            s.exit=Cpu64Exit::unsupported;break;
        }


        // CMOVE/CMOVZ r64, r/m64: register form.

        if(op==0x0f) {
            uint8_t opcode2=0;
            if(!fetch(pc,opcode2)) {
                s.exit=Cpu64Exit::memoryFault;
                break;
            }

            // BT r/m32 or r/m64, imm8: 0F BA /4 ib.
            if(opcode2==0xba) {
                uint8_t modrm=0;
                if(!fetch(pc,modrm)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                // /4 selects BT; register operands only.
                if((modrm&0xf8)!=0xe0) {
                    s.exit=Cpu64Exit::unsupported;
                    break;
                }

                uint8_t bit=0;
                if(!fetch(pc,bit)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned reg=
                    (modrm&7)+((rex&1)?8:0);
                const bool wide=(rex&8)!=0;
                const unsigned index=bit%(wide?64u:32u);

                s.cf=((s.gpr[reg]>>index)&1u)!=0;
                s.rip=pc;
                ++s.steps;
                continue;
            }

            // JAE/JNB rel32: jump when CF is clear.
            if(opcode2==0x83) {
                uint32_t raw=0;
                if(!imm32(raw)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                uint64_t dest=pc;
                if(!s.cf) {
                    const int64_t delta=
                        static_cast<int32_t>(raw);
                    dest=pc+static_cast<uint64_t>(delta);
                }

                if(memory.check(dest,1,
                   GuestMemory64::Execute)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.rip=dest;
                ++s.steps;
                continue;
            }

            if(opcode2==0xa2) {
                const uint32_t leaf=static_cast<uint32_t>(s.gpr[0]);
                uint32_t eax=0,ebx=0,ecx=0,edx=0;

                if(leaf==0) {
                    eax=1;
                    ebx=0x756e6547;
                    edx=0x49656e69;
                    ecx=0x6c65746e;
                } else if(leaf==1) {
                    eax=0x00000663;
                    // Do not advertise incomplete optional instruction groups.
                    edx=0;
                }

                s.gpr[0]=eax;
                s.gpr[3]=ebx;
                s.gpr[1]=ecx;
                s.gpr[2]=edx;
                s.rip=pc;
                ++s.steps;
                continue;
            }

            if(opcode2==0xb6) {
                uint8_t modrm=0;
                if(!fetch(pc,modrm)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                if((modrm&0xc7)!=0x05) {
                    s.exit=Cpu64Exit::unsupported;
                    break;
                }

                uint32_t raw=0;
                if(!imm32(raw)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                const unsigned dst=
                    ((modrm>>3)&7)+((rex&4)?8:0);

                const int64_t disp=
                    static_cast<int32_t>(raw);

                const uint64_t addr=
                    pc+static_cast<uint64_t>(disp);

                std::array<uint8_t,1> bytes{};
                if(memory.read(addr,bytes)!=
                   GuestMemory64::Fault::none) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                s.gpr[dst]=bytes[0];
                s.rip=pc;
                ++s.steps;
                continue;
            }


            if(opcode2==0x44) {
                uint8_t modrm=0;
                if(!fetch(pc,modrm)) {
                    s.exit=Cpu64Exit::memoryFault;
                    break;
                }

                if((modrm&0xc0)!=0xc0) {
                    s.exit=Cpu64Exit::unsupported;
                    break;
                }

                const unsigned dst=
                    ((modrm>>3)&7)+((rex&4)?8:0);
                const unsigned src=
                    (modrm&7)+((rex&1)?8:0);

                if(s.zf) {
                    if(rex&8)
                        s.gpr[dst]=s.gpr[src];
                    else
                        s.gpr[dst]=
                            static_cast<uint32_t>(s.gpr[src]);
                }

                s.rip=pc;
                ++s.steps;
                continue;
            }

            s.exit=Cpu64Exit::unsupported;
            break;
        }



        // RIP-relative MOV immediate store (C7 /0).
        if(op==0xc7) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            // Support only MOV [RIP+disp32], imm32.
            if(modrm!=0x05 || (rex&8)) {
                s.exit=Cpu64Exit::unsupported;break;
            }

            uint32_t displacement=0;
            uint32_t immediate=0;

            if(!imm32(displacement) || !imm32(immediate)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const uint64_t address=
                pc+static_cast<uint64_t>(
                    static_cast<int64_t>(
                        static_cast<int32_t>(displacement)));

            std::array<uint8_t,4> bytes{};
            for(unsigned i=0;i<4;++i)
                bytes[i]=static_cast<uint8_t>(
                    immediate>>(8*i));

            if(memory.write(address,bytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            s.rip=pc;
            ++s.steps;
            continue;
        }


        // RIP-relative MOV r32 store (89 /r).
        if(op==0x89 && !(rex&8)) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            if((modrm&0xc7)!=0x05) {
                s.exit=Cpu64Exit::unsupported;break;
            }

            uint32_t raw=0;
            if(!imm32(raw)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const unsigned src=
                ((modrm>>3)&7)+((rex&4)?8:0);

            const uint64_t addr=
                pc+static_cast<uint64_t>(
                    static_cast<int64_t>(
                        static_cast<int32_t>(raw)));

            const uint32_t value=
                static_cast<uint32_t>(s.gpr[src]);

            std::array<uint8_t,4> bytes{};
            for(unsigned i=0;i<4;++i)
                bytes[i]=static_cast<uint8_t>(
                    value>>(i*8));

            if(memory.write(addr,bytes)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            s.rip=pc;
            ++s.steps;
            continue;
        }

        // CMP r32/r64, r/m32/r/m64: register operands.
        if(op==0x3b) {
            uint8_t modrm=0;
            if(!fetch(pc,modrm)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            if((modrm&0xc0)!=0xc0) {
                s.exit=Cpu64Exit::unsupported;break;
            }

            const unsigned lhs=((modrm>>3)&7)+((rex&4)?8:0);
            const unsigned rhs=(modrm&7)+((rex&1)?8:0);
            const bool wide=(rex&8)!=0;
            const uint64_t mask=wide
                ? UINT64_MAX : UINT64_C(0xffffffff);
            const uint64_t sign=wide
                ? (UINT64_C(1)<<63) : (UINT64_C(1)<<31);

            const uint64_t a=s.gpr[lhs]&mask;
            const uint64_t b=s.gpr[rhs]&mask;
            const uint64_t result=(a-b)&mask;

            s.zf=(result==0);
            s.cf=(a<b);
            s.sf=(result&sign)!=0;
            s.of=(((a^b)&(a^result)&sign)!=0);

            uint8_t low=static_cast<uint8_t>(result);
            low^=low>>4;
            low^=low>>2;
            low^=low>>1;
            s.pf=((low&1)==0);

            s.rip=pc;
            ++s.steps;
            continue;
        }

        // JL/JNGE rel8: signed less-than.
        if(op==0x7c) {
            uint8_t raw=0;
            if(!fetch(pc,raw)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            const uint64_t dest=(s.sf!=s.of)
                ? pc+static_cast<uint64_t>(
                    static_cast<int64_t>(
                        static_cast<int8_t>(raw)))
                : pc;

            if(memory.check(dest,1,GuestMemory64::Execute)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }

            s.rip=dest;
            ++s.steps;
            continue;
        }

        // JNE/JNZ rel8: jump when Zero Flag is clear.
        if(op==0x75) {
            uint8_t raw=0;
            if(!fetch(pc,raw)) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            uint64_t dest=pc;
            if(!s.zf) {
                const int64_t delta=static_cast<int8_t>(raw);
                dest=pc+static_cast<uint64_t>(delta);
            }
            if(memory.check(dest,1,GuestMemory64::Execute)!=
               GuestMemory64::Fault::none) {
                s.exit=Cpu64Exit::memoryFault;break;
            }
            s.rip=dest;++s.steps;continue;
        }
        if(op==0xc3 || op==0xc2) {
            uint64_t adjustment=8;
            if(op==0xc2) {
                uint8_t lo=0,hi=0;
                if(!fetch(pc,lo)||!fetch(pc,hi)) {
                    s.exit=Cpu64Exit::memoryFault;break;
                }
                adjustment+=uint64_t(lo)|(uint64_t(hi)<<8);
            }
            std::array<uint8_t,8> ret{};
            if(memory.read(s.gpr[4],ret)!=GuestMemory64::Fault::none){
                s.exit=Cpu64Exit::memoryFault;break;
            }
            uint64_t dest=0;
            for(unsigned i=0;i<8;++i) dest|=uint64_t(ret[i])<<(8*i);
            if(memory.check(dest,1,GuestMemory64::Execute)!=GuestMemory64::Fault::none){
                s.exit=Cpu64Exit::memoryFault;break;
            }
            if(s.gpr[4]>UINT64_MAX-adjustment){s.exit=Cpu64Exit::memoryFault;break;}
            s.gpr[4]+=adjustment;s.rip=dest;++s.steps;continue;
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
