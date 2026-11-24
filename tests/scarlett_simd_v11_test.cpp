#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
 std::array<uint8_t,16> data{}; for(unsigned i=0;i<16;++i)data[i]=uint8_t(i+1);
 assert(m.write(0x1100,data)==GuestMemory64::Fault::none);
 // MOVDQA xmm0,[rip+f8]; MOVDQU [rip+f1],xmm0; PXOR xmm0,xmm0; INT3
 std::array<uint8_t,21> code{0x66,0x0f,0x6f,0x05,0xf8,0,0,0,0xf3,0x0f,0x7f,0x05,0xf1,0,0,0,0x66,0x0f,0xef,0xc0,0xcc};
 assert(m.write(0x1000,code)==GuestMemory64::Fault::none);
 auto s=executeGuest64(m,0x1000,10); assert(s.exit==Cpu64Exit::breakpoint && s.steps==4);
 std::array<uint8_t,16> out{},zero{}; assert(m.read(0x1101,out)==GuestMemory64::Fault::none && out==data && s.xmm[0]==zero);
 code[4]=0xf9; assert(m.write(0x1000,code)==GuestMemory64::Fault::none); s=executeGuest64(m,0x1000,10); assert(s.exit==Cpu64Exit::memoryFault && s.steps==0);
 std::cout<<"V11 SIMD tests passed\n";
}
