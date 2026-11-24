#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State i;i.gpr[2]=0x123456789abcdef0ull;i.cf=i.zf=i.of=i.sf=i.pf=true;auto run=[&](auto b){assert(m.write(0x1000,b)==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.steps==1&&s.cf&&s.zf&&s.of&&s.sf&&s.pf);return s;};for(unsigned k=0;k<256;++k){auto s=run(std::array<uint8_t,6>{0xc4,0x63,0x7b,0xf0,0xc2,uint8_t(k)});assert(s.gpr[8]==std::rotr(uint32_t(i.gpr[2]),int(k)));s=run(std::array<uint8_t,6>{0xc4,0x63,0xfb,0xf0,0xc2,uint8_t(k)});assert(s.gpr[8]==std::rotr(i.gpr[2],int(k)));}std::array<uint8_t,4> d{0x78,0x56,0x34,0x12};assert(m.write(0x1100,d)==GuestMemory64::Fault::none);auto s=run(std::array<uint8_t,10>{0xc4,0xe3,0x7b,0xf0,0x05,0xf6,0,0,0,8});assert(s.gpr[0]==0x78123456);std::cout<<"V56 RORX tests passed\n";}
