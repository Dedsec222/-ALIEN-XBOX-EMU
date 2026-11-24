#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; ScarlettImports64 im; using F=GuestMemory64::Fault;
 assert(im.install(m)); assert(m.map(0x1000,4096,7)==F::none); assert(m.map(0x8000,4096,3)==F::none);
 auto reg=im.registerImport("api-ms-win-crt-runtime-l1-1-0.dll","_crt_atexit");
 auto run=im.registerImport("api-ms-win-crt-runtime-l1-1-0.dll","_cexit");
 // Each callback stores a different byte at the same guest address.
 std::array<uint8_t,8> a{0xc6,0x05,0xf9,0x01,0,0,1,0xc3};
 std::array<uint8_t,8> b{0xc6,0x05,0xe9,0x01,0,0,2,0xc3};
 assert(m.write(0x1100,a)==F::none); assert(m.write(0x1110,b)==F::none);
 uint64_t r=9; assert(im.dispatch(reg,m,0x1100,r)&&r==0); assert(im.dispatch(reg,m,0x1110,r)&&r==0);
 std::array<uint8_t,2> call{0xff,0xd0}; assert(m.write(0x1000,call)==F::none);
 Cpu64State initial; initial.gpr[0]=run;
 auto s=executeGuest64(m,0x1000,100,0x8ff0,&im,0,0,0x1002,0,&initial);
 std::array<uint8_t,1> out{}; assert(m.read(0x1300,out)==F::none); assert(out[0]==1 && s.rip==0x1002 && s.steps==5 && !im.hasExitCallback());
 std::cout<<"V12 exit callback tests passed\n";
}
