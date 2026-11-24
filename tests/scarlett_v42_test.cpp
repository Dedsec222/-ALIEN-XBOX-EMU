#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State i;i.gpr[4]=0x1900;i.gpr[0]=10;i.gpr[1]=3;i.gpr[2]=1;auto run=[&](auto b){assert(m.write(0x1000,b)==GuestMemory64::Fault::none);return executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);};auto s=run(std::array<uint8_t,6>{0xf7,0xc2,0xfe,0xff,0xff,0xff});assert(s.steps==1&&s.zf&&!s.cf);s=run(std::array<uint8_t,3>{0x48,0xf7,0xe1});assert(s.gpr[0]==30&&s.gpr[2]==0);i.gpr[2]=0;s=run(std::array<uint8_t,3>{0x48,0xf7,0xf1});assert(s.gpr[0]==3&&s.gpr[2]==1);i.gpr[0]=uint64_t(-10);i.gpr[2]=~0ull;s=run(std::array<uint8_t,3>{0x48,0xf7,0xf9});assert(s.gpr[0]==uint64_t(-3)&&s.gpr[2]==~0ull);i.gpr[1]=0;s=run(std::array<uint8_t,3>{0x48,0xf7,0xf1});assert(s.steps==0&&s.gpr==i.gpr);std::cout<<"V42 tests passed\n";}
