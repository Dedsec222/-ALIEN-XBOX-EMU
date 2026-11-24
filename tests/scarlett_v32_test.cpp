#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;using F=GuestMemory64::Fault;assert(m.map(0x1000,4096,7)==F::none);Cpu64State init;init.gpr[0]=1;init.gpr[1]=2;auto run=[&](auto code){assert(m.write(0x1000,code)==F::none);return executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&init);};auto s=run(std::array<uint8_t,3>{0x0f,0xa3,0xc1});assert(s.steps==1&&s.cf&&s.gpr[1]==2);s=run(std::array<uint8_t,3>{0x0f,0xb3,0xc1});assert(s.cf&&s.gpr[1]==0);s=run(std::array<uint8_t,4>{0x66,0x0f,0xbb,0xc1});assert(s.cf&&s.gpr[1]==0);ScarlettImports64 imp;assert(imp.install(m));auto a=imp.registerImport("api-ms-win-crt-convert-l1-1-0.dll","strtol");assert(a);assert(m.write(0x1800,std::array<uint8_t,7>{' ','-','0','x','f','z',0})==F::none);uint64_t r=0;assert(imp.dispatch(a,m,0x1800,r,0x1900,0));assert(r==uint32_t(-15));std::array<uint8_t,8>b{};assert(m.read(0x1900,b)==F::none&&b[0]==5&&b[1]==0x18);std::cout<<"V32 tests passed\n";}
