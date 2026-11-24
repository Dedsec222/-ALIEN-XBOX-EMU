#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);unsigned count=0;
for(unsigned kind=0;kind<5;++kind)for(bool wide:{false,true})for(bool mem:{false,true})for(unsigned l=0;l<4;++l)for(unsigned r=0;r<4;++r){
unsigned w=1u<<std::min(kind,3u),n=wide?32:16;uint64_t sign=uint64_t(1)<<(w*8-1),mask=sign|(sign-1);uint64_t vals[]={0,sign,sign-1,mask};Cpu64State i;i.gpr[0]=0x1800;std::array<uint8_t,32>x{},y{};
for(unsigned j=0;j<n;j+=w){std::memcpy(x.data()+j,&vals[l],w);std::memcpy(y.data()+j,&vals[r],w);}std::memcpy(i.xmm[1].data(),x.data(),16);std::memcpy(i.ymmHigh[1].data(),x.data()+16,16);std::memcpy(i.xmm[0].data(),y.data(),16);std::memcpy(i.ymmHigh[0].data(),y.data()+16,16);assert(m.write(0x1800,y)==GuestMemory64::Fault::none);
assert(m.write(0x1000,std::array<uint8_t,5>{0xc4,uint8_t(kind<3?0xe1:0xe2),uint8_t(0x71|(wide?4:0)),uint8_t(kind<3?0x64+kind:kind==3?0x37:0x29),uint8_t(mem?0:0xc0)})==GuestMemory64::Fault::none);
auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1005);uint8_t expected=(kind==4?l==r:(vals[l]^sign)>(vals[r]^sign))?255:0;for(unsigned j=0;j<16;++j){assert(s.xmm[0][j]==expected);assert(s.ymmHigh[0][j]==(wide?expected:0));}++count;}
std::cout<<"V74 passed: "<<count<<" cases\n";}
