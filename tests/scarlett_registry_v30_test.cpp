#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m; using F=GuestMemory64::Fault; assert(m.map(0x1000,4096,3)==F::none); ScarlettImports64 i;assert(i.install(m));auto o=i.registerImport("ADVAPI32.dll","RegOpenKeyW"),c=i.registerImport("ADVAPI32.dll","RegCloseKey");assert(o&&c);uint64_t a=99;constexpr uint64_t root=0xffffffff80000002ull;assert(m.write(0x1000,std::array<uint8_t,4>{65,0,0,0})==F::none);assert(i.dispatch(o,m,root,a,0x1000,0x1100)&&a==2);assert(i.dispatch(o,m,root,a,0,0x1100)&&a==0);std::array<uint8_t,8>b{};assert(m.read(0x1100,b)==F::none&&b[0]==2&&b[3]==128&&b[7]==255);assert(i.dispatch(c,m,root,a)&&a==0);assert(i.dispatch(c,m,123,a)&&a==6);std::cout<<"V30 empty registry tests passed\n";}
