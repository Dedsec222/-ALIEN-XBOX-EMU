#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State i;i.gpr[7]=0x28;i.gpr[1]=0x403;auto run=[&](auto b){assert(m.write(0x1000,b)==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.steps==1);return s;};auto s=run(std::array<uint8_t,5>{0xc4,0xe2,0x78,0xf3,0xdf});assert(s.gpr[0]==8&&s.cf&&!s.zf);s=run(std::array<uint8_t,5>{0xc4,0xe2,0x78,0xf3,0xcf});assert(s.gpr[0]==32&&!s.cf);s=run(std::array<uint8_t,5>{0xc4,0xe2,0x78,0xf3,0xd7});assert(s.gpr[0]==15);s=run(std::array<uint8_t,5>{0xc4,0xe2,0x70,0xf7,0xc7});assert(s.gpr[0]==5);s=run(std::array<uint8_t,5>{0xc4,0xe2,0x70,0xf2,0xc7});assert(s.gpr[0]==40);i.gpr[7]=0;s=run(std::array<uint8_t,5>{0xc4,0xe2,0x78,0xf3,0xdf});assert(s.zf&&!s.cf);std::cout<<"V45 BMI tests passed\n";}
