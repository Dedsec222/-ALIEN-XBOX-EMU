#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State i;i.gpr[0]=~0ull;i.gpr[2]=2;i.cf=true;i.zf=true;auto run=[&](auto b){assert(m.write(0x1000,b)==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.steps==1&&s.cf&&s.zf);return s;};auto s=run(std::array<uint8_t,5>{0xc4,0xe2,0xfb,0xf6,0xc0});assert(s.gpr[0]==1);s=run(std::array<uint8_t,5>{0xc4,0xe2,0xf3,0xf6,0xc0});assert(s.gpr[0]==1&&s.gpr[1]==~1ull);i.gpr[0]=0x80;i.gpr[1]=3;s=run(std::array<uint8_t,5>{0xc4,0xe2,0x71,0xf7,0xc0});assert(s.gpr[0]==1024);i.gpr[0]=0x55;i.gpr[1]=0xf;s=run(std::array<uint8_t,5>{0xc4,0xe2,0x73,0xf5,0xc0});assert(s.gpr[0]==0x55);s=run(std::array<uint8_t,5>{0xc4,0xe2,0x72,0xf5,0xc0});assert(s.gpr[0]==3);std::cout<<"V53 BMI2 tests passed\n";}
