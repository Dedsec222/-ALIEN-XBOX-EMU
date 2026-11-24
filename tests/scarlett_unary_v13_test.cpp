#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
 auto run=[&](std::initializer_list<uint8_t> code){assert(m.write(0x1000,std::span<const uint8_t>(code.begin(),code.size()))==GuestMemory64::Fault::none);return executeGuest64(m,0x1000,30);};
 auto s=run({0xb8,1,0,0,0,0x48,0xf7,0xd8,0xcc}); assert(s.exit==Cpu64Exit::breakpoint && s.gpr[0]==UINT64_MAX && s.cf && s.sf && !s.of);
 s=run({0xb8,0,0,0,0,0xf7,0xd8,0xcc}); assert(s.gpr[0]==0 && s.zf && !s.cf && s.pf);
 s=run({0xb8,0,0,0,0x80,0xf7,0xd8,0xcc}); assert(s.gpr[0]==0x80000000 && s.of && s.cf);
 s=run({0xb8,1,0,0,0,0x48,0xf7,0xd8,0x1b,0xc0,0xf7,0xd8,0xff,0xc8,0xcc}); assert(s.exit==Cpu64Exit::breakpoint && s.gpr[0]==0);
 s=run({0xb8,1,0,0,0,0xf6,0xd8,0xf6,0xd0,0xcc}); assert(s.gpr[0]==0 && s.cf && s.sf);
 s=run({0xf7,0x1d,0xfa,0,0,0,0xcc}); assert(s.exit==Cpu64Exit::breakpoint && s.zf);
 std::cout<<"V13 unary tests passed\n";
}
