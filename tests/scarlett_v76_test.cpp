#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);unsigned total=0;
for(unsigned op:{0x45u,0x46u,0x47u,8u,9u,10u,28u,29u,30u})for(bool wide:{false,true})for(bool mem:{false,true})for(bool q:{false,true}){
 bool shift=op>=0x45,abs=op>=28&&!shift;if(q&&(!shift||op==0x46))continue;
 unsigned w=shift?(q?8:4):1u<<(op-(abs?28:8)),n=wide?32:16,bits=w*8;uint64_t mask=~uint64_t(0)>>(64-bits),sg=uint64_t(1)<<(bits-1);
 for(uint64_t r:{uint64_t(0),uint64_t(1),uint64_t(bits-1),uint64_t(bits),sg,mask}){
 Cpu64State i;i.gpr[0]=0x1800;std::array<uint8_t,32>x{},y{};uint64_t l=sg+3;r&=mask;
 for(unsigned j=0;j<n;j+=w){std::memcpy(x.data()+j,&l,w);std::memcpy(y.data()+j,&r,w);}std::memcpy(i.xmm[1].data(),x.data(),16);std::memcpy(i.ymmHigh[1].data(),x.data()+16,16);std::memcpy(i.xmm[0].data(),y.data(),16);std::memcpy(i.ymmHigh[0].data(),y.data()+16,16);assert(m.write(0x1800,y)==GuestMemory64::Fault::none);
 assert(m.write(0x1000,std::array<uint8_t,5>{0xc4,0xe2,uint8_t((abs?0x79:0x71)|(wide?4:0)|(q?128:0)),uint8_t(op),uint8_t(mem?0:0xc0)})==GuestMemory64::Fault::none);
 auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1005);uint64_t expected=0;
 if(abs)expected=(r&sg)?-r:r;else if(!shift)expected=(r&sg)?-l:r?l:0;else if(op==0x46)expected=r>=bits?mask: uint64_t(int32_t(l)>>r);else if(r<bits)expected=op==0x45?l>>r:l<<r;
 for(unsigned j=0;j<n;j+=w){uint64_t got=0;std::memcpy(&got,j<16?s.xmm[0].data()+j:s.ymmHigh[0].data()+j-16,w);assert(got==(expected&mask));}if(!wide)for(auto b:s.ymmHigh[0])assert(b==0);++total;
 }}
std::cout<<"V76 passed: "<<total<<" cases\n";}
