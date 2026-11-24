#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;using F=GuestMemory64::Fault;assert(m.map(0x1000,4096,7)==F::none);Cpu64State init;init.gpr[0]=0x1800;init.gpr[3]=0x123456789abcffffull;
std::array<uint8_t,9> code{0x66,0xc7,0x80,0x10,0,0,0,0x34,0x12};assert(m.write(0x1000,code)==F::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&init);assert(s.steps==1&&s.rip==0x1009);std::array<uint8_t,3> b{};assert(m.read(0x1810,b)==F::none&&b[0]==0x34&&b[1]==0x12&&b[2]==0);
std::array<uint8_t,4> add{0x66,0x83,0xc3,1};assert(m.write(0x1000,add)==F::none);s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&init);assert(s.gpr[3]==0x123456789abc0000ull&&s.cf&&s.zf);
ScarlettImports64 imp;assert(imp.install(m));uint64_t r=0;auto call=[&](const char* n,uint64_t a,uint64_t b=0,uint64_t c=0){auto f=imp.registerImport("api-ms-win-crt-string-l1-1-0.dll",n);assert(f&&imp.dispatch(f,m,a,r,b,c));};call("isalpha",'A');assert(r);call("isdigit",'A');assert(!r);std::array<uint8_t,4> x{'A','b','C',0},y{'a','B','c',0};assert(m.write(0x1820,x)==F::none&&m.write(0x1830,y)==F::none);call("_stricmp",0x1820,0x1830);assert(!r);call("strcspn",0x1820,0x1830);assert(r==3);std::cout<<"V28 tests passed\n";}
