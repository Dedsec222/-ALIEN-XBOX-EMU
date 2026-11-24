#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;using F=GuestMemory64::Fault;assert(m.map(0x1000,4096,7)==F::none);Cpu64State init;for(unsigned i=0;i<16;++i)init.xmm[0][i]=i;init.gpr[1]=0x123456789abcdef0ULL;auto run=[&](auto code){assert(m.write(0x1000,code)==F::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&init);assert(s.steps==1&&s.rip==0x1000+code.size());return s;};auto s=run(std::array<uint8_t,6>{0xc4,0xe3,0xf9,0x16,0xc1,1});assert(s.gpr[1]==0x0f0e0d0c0b0a0908ULL);s=run(std::array<uint8_t,6>{0xc4,0xe3,0x79,0x14,0xc1,15});assert(s.gpr[1]==15);s=run(std::array<uint8_t,6>{0xc4,0xe3,0xf9,0x22,0xc1,1});assert(s.xmm[0][8]==0xf0&&s.xmm[0][15]==0x12&&s.xmm[0][7]==7);std::cout<<"V41 tests passed\n";}
