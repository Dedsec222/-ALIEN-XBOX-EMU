#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; ScarlettImports64 im;
 assert(im.install(m));
 auto f=im.registerImport("api-ms-win-crt-runtime-l1-1-0.dll","_initterm_e");
 assert(f);
 assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
 assert(m.map(0x8000,4096,3)==GuestMemory64::Fault::none);
 std::array<uint8_t,2> call{0xff,0xd0};
 std::array<uint8_t,6> fn{0xb8,7,0,0,0,0xc3};
 std::array<uint8_t,8> ptr{0x00,0x11};
 assert(m.write(0x1000,call)==GuestMemory64::Fault::none);
 assert(m.write(0x1100,fn)==GuestMemory64::Fault::none);
 assert(m.write(0x1200,ptr)==GuestMemory64::Fault::none);
 Cpu64State initial; initial.gpr[0]=f; initial.gpr[1]=0x1200; initial.gpr[2]=0x1208;
 auto s=executeGuest64(m,0x1000,100,0x8ff0,&im,0,0,0x1002,0,&initial);
 assert(s.rip==0x1002 && s.gpr[0]==7 && s.steps==3 && s.gpr[4]==0x8ff0);
 std::cout<<"CRT callback test passed\\n";
}
