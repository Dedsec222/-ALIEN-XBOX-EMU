#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m; ScarlettImports64 im; assert(im.install(m)); constexpr uint64_t base=0x140000000; assert(m.map(base,4096,3)==GuestMemory64::Fault::none); im.setImageBase(base);im.setExceptionDirectory(4096,256,24);std::array<uint8_t,24>b{0,2,0,0,0,3,0,0,0,5,0,0,0,4,0,0,0,5,0,0,0,6,0,0};assert(m.write(base+256,b)==GuestMemory64::Fault::none);auto fn=im.registerImport("api-ms-win-core-rtlsupport-l1-1-0.dll","RtlLookupFunctionEntry");uint64_t r=0;assert(fn);assert(im.dispatch(fn,m,base+0x200,r,base+0x80)&&r==base+256);assert(im.dispatch(fn,m,base+0x400,r,base+0x80)&&r==base+268);assert(im.dispatch(fn,m,base+0x300,r,base+0x80)&&!r);assert(!im.dispatch(fn,m,base+0x200,r,0));std::array<uint8_t,8> out{};assert(m.read(base+0x80,out)==GuestMemory64::Fault::none);assert(out[3]==0x40&&out[4]==1);std::cout<<"V20 function lookup tests passed\n";}
