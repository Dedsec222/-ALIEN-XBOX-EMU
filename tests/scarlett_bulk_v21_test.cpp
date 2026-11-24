#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;ScarlettImports64 im;assert(im.install(m));assert(m.map(0x10000,4096,3)==GuestMemory64::Fault::none);std::array<uint8_t,4>b{'a','B','a',0};assert(m.write(0x10000,b)==GuestMemory64::Fault::none);uint64_t r=0;auto f=im.registerImport("VCRUNTIME140.dll","strrchr");assert(f&&im.dispatch(f,m,0x10000,r,'a')&&r==0x10002);f=im.registerImport("api-ms-win-crt-string-l1-1-0.dll","strcpy");assert(f&&im.dispatch(f,m,0x10010,r,0x10000)&&r==0x10010);std::array<uint8_t,4> out{};assert(m.read(0x10010,out)==GuestMemory64::Fault::none&&out==b);f=im.registerImport("api-ms-win-crt-string-l1-1-0.dll","toupper");assert(f&&im.dispatch(f,m,'a',r)&&r=='A');std::cout<<"V21 bulk smoke tests passed\n";}
