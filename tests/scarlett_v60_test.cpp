#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State i;i.ymmHigh[0].fill(255);std::array<uint8_t,16> data{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};assert(m.write(0x1800,data)==GuestMemory64::Fault::none);auto run=[&](uint8_t b,uint8_t op){assert(m.write(0x1000,std::array<uint8_t,9>{0xc4,0xe2,b,op,5,0xf7,7,0,0})==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.steps==1&&s.rip==0x1009);return s;};for(auto op:{0x18,0x19,0x1a}){auto s=run(0x7d,op);unsigned w=op==0x18?4:op==0x19?8:16;for(unsigned j=0;j<16;++j){assert(s.xmm[0][j]==data[j%w]);assert(s.ymmHigh[0][j]==data[(j+16)%w]);}}auto s=run(0x79,0x18);for(unsigned j=0;j<16;++j){assert(s.xmm[0][j]==data[j%4]);assert(s.ymmHigh[0][j]==0);}std::cout<<"V60 AVX broadcast tests passed\n";}
