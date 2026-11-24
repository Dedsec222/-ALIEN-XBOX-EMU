#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;ScarlettImports64 imp;assert(imp.install(m));assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);auto p=imp.registerImport("api-ms-win-core-synch-l1-1-0.dll","CreateSemaphoreExW");assert(p);auto put=[&](uint64_t a,uint64_t v){std::array<uint8_t,8>b{};for(unsigned j=0;j<8;++j)b[j]=v>>(8*j);assert(m.write(a,b)==GuestMemory64::Fault::none);};put(0x1100,p);put(0x1820,0);put(0x1828,0x1f0003);assert(m.write(0x1000,std::array<uint8_t,6>{0xff,0x15,0xfa,0,0,0})==GuestMemory64::Fault::none);Cpu64State i;i.gpr[4]=0x1800;i.gpr[8]=0x7fff;auto s=executeGuest64(m,0x1000,1,0x1800,&imp,0,0,0,0,&i);assert(s.steps==1&&s.gpr[0]&&s.rip==0x1006);std::cout<<"V44 ABI integration passed\n";}
