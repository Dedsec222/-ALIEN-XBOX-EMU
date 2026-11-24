#include "scarlett_probe.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
using F=GuestMemory64::Fault;
int main() {
    GuestMemory64 mem;
    assert(mem.map(0x1000,4096,7)==F::none);
    assert(mem.map(0x2000,4096,3)==F::none);
    auto run=[&](const std::vector<uint8_t>& bytes,const Cpu64State& input) {
        assert(mem.write(0x1000,bytes)==F::none);
        return executeGuest64(mem,0x1000,1,input.gpr[4],nullptr,0,0,0,0,&input);
    };
    Cpu64State input;
    input.cf=input.sf=input.pf=input.zf=input.of=true;
    for (unsigned width:{4u,8u}) for(unsigned r=0;r<16;++r) {
        input.gpr[r]=0x123456789abcdef0;
        std::vector<uint8_t> code;
        if(width==8 || r>=8) code.push_back(0x40+(width==8?8:0)+(r>=8));
        code.insert(code.end(),{0x0f,uint8_t(0xc8+r%8)});
        auto result=run(code,input);
        assert(result.rip==0x1000+code.size() && result.gpr[r]==(width==8?0xf0debc9a78563412ULL:0xf0debc9aULL));
        assert(result.cf&&result.sf&&result.pf&&result.zf&&result.of);
    }
    for (unsigned width:{2u,4u,8u}) {
        std::vector<uint8_t> code;
        if(width!=4) code.push_back(width==8?0x48:0x66);
        code.insert(code.end(),{0x0f,0x38,0xf1,0x08});
        input.gpr[0]=0x2081;
        input.gpr[1]=0x123456789abcdef0;
        assert(run(code,input).rip==0x1000+code.size());
        std::array<uint8_t,8> bytes{};
        assert(mem.read(0x2081,bytes)==F::none && bytes[width-1]==0xf0);
        code[code.size()-2]=0xf0;
        auto result=run(code,input);
        assert(result.gpr[1]==(width==4?0x9abcdef0:input.gpr[1]));
        input.gpr[0]=0x2fff;
        assert(run(code,input).exit==Cpu64Exit::memoryFault);
    }
    unsigned vectorCases=0;
    for (unsigned ext:{0xdau,0xdeu,0xeau,0xeeu,0x38u,0x39u,0x3au,0x3bu,0x3cu,0x3du,0x3eu,0x3fu})
    for(unsigned encoding=0;encoding<3;++encoding) for(bool memory:{true,false}) {
        const bool map2=ext<0x40;
        unsigned w=map2?std::array<unsigned,4>{1,4,2,4}[ext%4]:ext>=0xe0?2:1;
        bool signedValue=map2?ext%4<2:w==2;
        const unsigned width=encoding==2?32:16;
        std::vector<uint8_t> bytes;
        if (!encoding) {bytes={0x66,0x0f};if(map2)bytes.push_back(0x38);}
        else bytes={0xc4,uint8_t(map2?0xe2:0xe1),uint8_t(encoding==2?0x75:0x71)};
        bytes.insert(bytes.end(),{uint8_t(ext),uint8_t(memory?0x00:0xc2)});
        input.gpr[0]=0x2100;
        std::array<uint8_t,32> right{};
        for(unsigned j=0;j<32;++j) {
            auto& bank=j<16?input.xmm:input.ymmHigh;
            bank[encoding?1:0][j%16]=uint8_t(31*j+198);
            bank[2][j%16]=right[j]=uint8_t(71*j+14);
        }
        assert(mem.write(input.gpr[0],right)==F::none);
        auto result=run(bytes,input);
        assert(result.rip==0x1000+bytes.size());
        for(unsigned j=0;j<width;j+=w) {
            const auto& src=(j<16?input.xmm:input.ymmHigh)[encoding?1:0];
            uint32_t a=0,b=0,actual=0;
            std::memcpy(&a,src.data()+j%16,w);
            std::memcpy(&b,right.data()+j,w);
            std::memcpy(&actual,(j<16?result.xmm:result.ymmHigh)[0].data()+j%16,w);
            auto value=[&](uint32_t x)->int64_t {
                if(!signedValue)return x;
                return w==1?int8_t(x):w==2?int16_t(x):int32_t(x);
            };
            assert(value(actual)==((ext&4)?std::max(value(a),value(b)):std::min(value(a),value(b))));
        }
        if(encoding==1)assert((result.ymmHigh[0]==std::array<uint8_t,16>{}));
        if(!encoding)assert(result.ymmHigh[0]==input.ymmHigh[0]);
        ++vectorCases;
    }
    assert(scarlettProbe().find("PASS")!=std::string::npos);
    std::cout<<"32 BSWAP forms, MOVBE loads/stores/faults, "<<vectorCases<<" vector forms, Android CPU probe passed\n";
}
