#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m; ScarlettImports64 h; assert(h.install(m)); assert(m.map(0x10000,4096,3)==GuestMemory64::Fault::none); auto put=[&](uint64_t a,std::vector<uint8_t> b){assert(m.write(a,b)==GuestMemory64::Fault::none);}; put(0x10000,{'%','d',0});put(0x10100,{42,0,0,0,0,0,0,0}); auto a=h.registerImport("api-ms-win-crt-stdio-l1-1-0.dll","__stdio_common_vsprintf");assert(a);uint64_t r=0;assert(h.dispatch(a,m,0x26,r,0x10200,2,0x10000,0,0x10100));assert(r==2);std::vector<uint8_t>b(2);assert(m.read(0x10200,b)==GuestMemory64::Fault::none);assert(b[0]=='4'&&b[1]==0);assert(!h.dispatch(a,m,0x80,r,0x10200,2,0x10000,0,0x10100));std::cout<<"V86.1 CRT option regression passed\n";}
