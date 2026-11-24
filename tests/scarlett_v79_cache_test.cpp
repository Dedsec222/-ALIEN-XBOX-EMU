#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m;
 assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
 assert(m.map(0x2000,4096,3)==GuestMemory64::Fault::none);
 auto epoch=m.codeGeneration();
 assert(m.write(0x2000,std::array<uint8_t,1>{1})==GuestMemory64::Fault::none);
 assert(m.codeGeneration()==epoch);
 assert(m.write(0x1000,std::array<uint8_t,4>{0x31,0xc0,0xeb,0xfc})==GuestMemory64::Fault::none);
 assert(m.codeGeneration()!=epoch);
 Arm64Blocks b;
 auto run=[&](Arm64Blocks* p){return executeGuest64(m,0x1000,10000,0x2800,nullptr,0,0,0,0,nullptr,p);};
 auto a=run(nullptr), c=run(&b);
 assert(a.gpr==c.gpr && a.rip==c.rip && a.steps==c.steps && a.exit==c.exit);
#if defined(__aarch64__) && defined(__linux__)
 assert(b.compileAttempts==2 && b.negativeHits==9998);
#endif
 assert(m.initialize(0x1000,std::array<uint8_t,4>{0x90,0x90,0xeb,0xfc})==GuestMemory64::Fault::none);
 a=run(nullptr); c=run(&b);
 assert(a.gpr==c.gpr && a.rip==c.rip && a.steps==c.steps && a.exit==c.exit);
#if defined(__aarch64__) && defined(__linux__)
 assert(b.calls>0);
#endif
 std::cout<<"V79 cache regression passed\n";
}
