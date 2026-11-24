#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);unsigned count=0;
 for(unsigned wide:{0u,4u})for(unsigned imm=0;imm<256;++imm)for(bool mem:{false,true}){
 Cpu64State i;i.gpr[0]=0x1800;std::array<uint8_t,32> data{};
 for(unsigned j=0;j<32;++j){(j<16?i.xmm[0]:i.ymmHigh[0])[j%16]=j;(j<16?i.xmm[2]:i.ymmHigh[2])[j%16]=data[j]=j+64;}
 assert(m.write(0x1800,data)==GuestMemory64::Fault::none);
 assert(m.write(0x1000,std::array<uint8_t,5>{0xc5,uint8_t(0xf8|wide),0xc6,uint8_t(mem?8:0xca),uint8_t(imm)})==GuestMemory64::Fault::none);
 auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1005);
 for(unsigned j=0;j<32;++j){unsigned lane=j&16,k=(j%16)/4;unsigned expected=lane+4*((imm>>(2*k))&3)+j%4+(k>=2?64:0);if(j>=16&&!wide)expected=0;assert((j<16?s.xmm[1]:s.ymmHigh[1])[j%16]==expected);}++count;
 }
 std::cout<<"V64 VSHUFPS tests passed: "<<count<<" cases\n";
}
