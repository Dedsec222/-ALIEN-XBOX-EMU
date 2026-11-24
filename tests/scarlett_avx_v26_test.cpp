#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);Cpu64State init;init.xmm[6].fill(0x5a);init.ymmHigh[6].fill(0xa5);
std::array<uint8_t,6> code{0xc5,0xf8,0x29,0x74,0x24,0x20};assert(m.write(0x1000,code)==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1800,nullptr,0,0,0,0,&init);assert(s.steps==1);std::array<uint8_t,16> out{};assert(m.read(0x1820,out)==GuestMemory64::Fault::none&&out==init.xmm[6]);s=executeGuest64(m,0x1000,1,0x1801,nullptr,0,0,0,0,&init);assert(s.exit==Cpu64Exit::memoryFault);
std::array<uint8_t,4> x{0xc5,0xcc,0x57,0xc6};assert(m.write(0x1000,x)==GuestMemory64::Fault::none);s=executeGuest64(m,0x1000,1,0x1800,nullptr,0,0,0,0,&init);assert(s.steps==1&&s.xmm[0]==Cpu64State{}.xmm[0]&&s.ymmHigh[0]==Cpu64State{}.ymmHigh[0]);std::cout<<"V26 AVX tests passed\n";}
