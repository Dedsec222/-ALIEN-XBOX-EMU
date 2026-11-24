#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);unsigned count=0;
for(unsigned op=8;op<=11;++op)for(unsigned wide:{0u,4u})for(unsigned mode=0;mode<4;++mode)for(bool mem:{false,true})for(bool mx:{false,true}){
 if(op>=10&&wide)continue;
 Cpu64State i;i.gpr[0]=0x1800;i.mxcsr=0x1f80|(mode<<13);i.xmm[0].fill(0x55);i.ymmHigh[1].fill(0xff);
 std::array<uint8_t,32> data{};double expected[4]={-2,-3,-2,-2};
 auto fill=[&]<typename T>(){for(unsigned j=0;j<32;j+=sizeof(T)){T v=-2.5;std::memcpy(data.data()+j,&v,sizeof(T));}};
 if(op&1)fill.template operator()<double>();else fill.template operator()<float>();
 std::memcpy(i.xmm[2].data(),data.data(),16);std::memcpy(i.ymmHigh[2].data(),data.data()+16,16);
 assert(m.write(0x1800,data)==GuestMemory64::Fault::none);
 assert(m.write(0x1000,std::array<uint8_t,6>{0xc4,0xe3,uint8_t(0x79|wide),uint8_t(op),uint8_t(mem?8:0xca),uint8_t(mx?4:mode)})==GuestMemory64::Fault::none);
 auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1006);
 unsigned w=op&1?8:4, bytes=op>=10?w:wide?32:16;
 for(unsigned j=0;j<bytes;j+=w){auto &v=j<16?s.xmm[1]:s.ymmHigh[1];if(w==8){double z;std::memcpy(&z,v.data()+j%16,8);assert(z==expected[mode]);}else{float z;std::memcpy(&z,v.data()+j%16,4);assert(z==expected[mode]);}}
 if(op>=10)for(unsigned j=w;j<16;++j)assert(s.xmm[1][j]==0x55);
 if(!wide)for(auto v:s.ymmHigh[1])assert(v==0);
 ++count;
}
std::cout<<"V65 rounding tests passed: "<<count<<" cases\n";
}
