#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
 for(unsigned pp:{0u,1u}) {
  for(unsigned wide:{0u,4u}) {
   for(unsigned op:{0x51u,0x52u,0x53u,0x58u,0x59u,0x5cu,0x5eu}) {
    if(pp && (op==0x52||op==0x53)) continue;
    auto test=[&]<typename T>() {
     Cpu64State i; T a=8,b=4;
     for(unsigned j=0;j<16;j+=sizeof(T)) {
      std::memcpy(i.xmm[1].data()+j,&a,sizeof(T));std::memcpy(i.xmm[2].data()+j,&b,sizeof(T));
      std::memcpy(i.ymmHigh[1].data()+j,&a,sizeof(T));std::memcpy(i.ymmHigh[2].data()+j,&b,sizeof(T));
     }
     assert(m.write(0x1000,std::array<uint8_t,4>{0xc5,uint8_t((op<=0x53?0xf8:0xf0)|pp|wide),uint8_t(op),0xc2})==GuestMemory64::Fault::none);
     auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1004);
     T expected=op==0x51?2:op==0x52?0.5:op==0x53?0.25:op==0x58?12:op==0x59?32:op==0x5c?4:2;
     for(unsigned lane=0;lane<2;++lane) {
      for(unsigned j=0;j<16;j+=sizeof(T)) {T got;std::memcpy(&got,(lane?s.ymmHigh[0]:s.xmm[0]).data()+j,sizeof(T));assert(got==(lane&&!wide?0:expected));}
     }
    };
    if(pp) test.template operator()<double>();else test.template operator()<float>();
   }
  }
 }
 std::cout<<"V62 packed arithmetic tests passed\n";
}
