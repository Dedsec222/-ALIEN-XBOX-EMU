#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State i;for(unsigned j=0;j<16;++j){i.xmm[0][j]=j;i.ymmHigh[0][j]=j+16;i.xmm[1][j]=j+32;i.ymmHigh[1][j]=j+48;}auto run=[&](auto b){assert(m.write(0x1000,b)==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.steps==1);return s;};for(unsigned k=0;k<256;++k){auto s=run(std::array<uint8_t,6>{0xc4,0xe3,0xfd,0x00,0xc0,uint8_t(k)});for(unsigned j=0;j<32;++j)assert((j<16?s.xmm[0][j]:s.ymmHigh[0][j-16])==((k>>(2*(j/8)))&3)*8+j%8);}auto s=run(std::array<uint8_t,6>{0xc4,0xe3,0x7d,0x46,0xc1,0x83});assert(s.xmm[0]==i.ymmHigh[1]);for(auto v:s.ymmHigh[0])assert(v==0);std::cout<<"V47 permutation tests passed\n";}
