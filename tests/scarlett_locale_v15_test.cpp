#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m; ScarlettImports64 im; assert(im.install(m)); auto a=im.registerImport("api-ms-win-crt-locale-l1-1-0.dll","_configthreadlocale"); assert(a); uint64_t r=0; auto call=[&](uint64_t x,uint64_t expected){assert(im.dispatch(a,m,x,r)&&r==expected);}; call(0,2);call(1,2);call(0,1);call(2,1);call(3,UINT32_MAX);call(0,2);std::array<uint8_t,4>b{};assert(m.read(im.CrtBase+24,b)==GuestMemory64::Fault::none&&b[0]==22);im.recordMissing(123,"dll!symbol");assert(im.missingName(123)=="dll!symbol"&&im.missingName(124).empty());std::cout<<"V15 locale tests passed\n";}
