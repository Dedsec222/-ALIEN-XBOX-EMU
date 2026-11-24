#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
    GuestMemory64 m;
    assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
    unsigned cases=0;
    for(unsigned op:{1u,2u,3u,4u,5u,6u,7u,11u})
    for(unsigned encoding:{0u,1u,2u})for(bool mem:{true,false}){
        Cpu64State initial;
        initial.gpr[0]=0x1200;
        std::array<uint8_t,32> x{},y{};
        for(unsigned i=0;i<32;++i){
            x[i]=uint8_t(0xef+13*i);y[i]=uint8_t(0x41+7*i);
            (i<16?initial.xmm:initial.ymmHigh)[encoding?1:0][i%16]=x[i];
            (i<16?initial.xmm:initial.ymmHigh)[2][i%16]=y[i];
        }
        assert(m.write(0x1200,y)==GuestMemory64::Fault::none);
        std::vector<uint8_t> code;
        if(encoding)code={0xc4,0xe2,uint8_t(encoding==2?0x75:0x71)};
        else code={0x66,0x0f,0x38};
        code.insert(code.end(),{uint8_t(op),uint8_t(mem?0:0xc2)});
        assert(m.write(0x1000,code)==GuestMemory64::Fault::none);
        auto cpu=executeGuest64(m,0x1000,1,0,nullptr,0,0,0,0,&initial);
        assert(cpu.rip==0x1000+code.size());
        for(unsigned base=0;base<(encoding==2?32u:16u);base+=16){
            const auto& result=base?cpu.ymmHigh[0]:cpu.xmm[0];
            const unsigned w=(op==2 || op==6)?4:2;
            auto get=[](const auto& arr,unsigned i,unsigned size)->int64_t {
                if(size==2)return int16_t(arr[i]|(unsigned(arr[i+1])<<8));
                uint32_t n=0;for(unsigned j=0;j<4;++j)n|=uint32_t(arr[i+j])<<(j*8);
                return int32_t(n);
            };
            for(unsigned j=0;j<16;j+=w){
                int64_t v;
                if(op==4)v=std::clamp(x[base+j]*int8_t(y[base+j])+x[base+j+1]*int8_t(y[base+j+1]),-32768,32767);
                else if(op==11)v=(get(x,base+j,2)*get(y,base+j,2)+16384)>>15;
                else {
                    const auto& pair=j<8?x:y;
                    unsigned offset=base+(j%8)*2;
                    auto a=get(pair,offset,w),b=get(pair,offset+w,w);
                    v=op<=3?a+b:a-b;
                    if(op==3 || op==7)v=std::clamp<int64_t>(v,-32768,32767);
                }
                assert(get(result,j,w)==(w==2?int16_t(v):int32_t(v)));
            }
        }
        ++cases;
    }
    std::cout<<cases<<" horizontal and multiply forms passed\n";
}
