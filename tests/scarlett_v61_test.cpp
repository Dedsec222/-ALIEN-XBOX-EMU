#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State i;
for(unsigned pp:{1u,3u})for(unsigned wide:{0u,4u})for(unsigned op:{0x7cu,0x7du,0xd0u}){
auto test=[&]<typename T>(){constexpr unsigned k=16/sizeof(T);for(unsigned j=0;j<k;++j){T a=j+1,b=j+5,c=j+10,d=j+20;std::memcpy(i.xmm[1].data()+j*sizeof(T),&a,sizeof(T));std::memcpy(i.xmm[2].data()+j*sizeof(T),&b,sizeof(T));std::memcpy(i.ymmHigh[1].data()+j*sizeof(T),&c,sizeof(T));std::memcpy(i.ymmHigh[2].data()+j*sizeof(T),&d,sizeof(T));}assert(m.write(0x1000,std::array<uint8_t,4>{0xc5,uint8_t(0xf0|pp|wide),uint8_t(op),0xc2})==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1004);for(unsigned lane=0;lane<2;++lane)for(unsigned j=0;j<k;++j){T got;std::memcpy(&got,(lane?s.ymmHigh[0]:s.xmm[0]).data()+j*sizeof(T),sizeof(T));T a=lane?10:1,b=lane?20:5;T base=(j<k/2?a:b)+2*(j%(k/2));T expected=op==0x7c?2*base+1:op==0x7d?-1:j%2?a+b+2*j:a-b;assert(got==(lane&&!wide?0:expected));}};if(pp==1)test.template operator()<double>();else test.template operator()<float>();}
std::cout<<"V61 horizontal arithmetic tests passed\n";}
