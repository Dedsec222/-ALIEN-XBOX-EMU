#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none); assert(m.map(0x2000,4096,3)==GuestMemory64::Fault::none);
 std::array<uint8_t,8> ret{0x10,0x10}; assert(m.write(0x2800,ret)==GuestMemory64::Fault::none);
 std::array<uint8_t,1> stop{0xcc}; assert(m.write(0x1010,stop)==GuestMemory64::Fault::none);
 for(unsigned n: {0u,32u,65535u}){std::array<uint8_t,3> code{0xc2,uint8_t(n),uint8_t(n>>8)};assert(m.write(0x1000,code)==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,10,0x2800);assert(s.exit==Cpu64Exit::breakpoint && s.gpr[4]==0x2808+n);}
 std::array<uint8_t,1> code{0xc2};assert(m.write(0x1fff,code)==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1fff,10,0x2800);assert(s.exit==Cpu64Exit::memoryFault && s.gpr[4]==0x2800);
 std::cout<<"V14 RET tests passed\n";
}
