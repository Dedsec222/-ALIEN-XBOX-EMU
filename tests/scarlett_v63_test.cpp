#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
 unsigned count=0;
 for(unsigned order=9;order<=11;++order)for(unsigned kind=6;kind<=15;++kind)for(unsigned wide:{0u,4u})for(unsigned w:{0u,128u})for(bool mem:{false,true}){
 bool scalar=kind>=8&&(kind&1);if(scalar&&wide)continue;
 auto test=[&]<typename T>(){
 Cpu64State i; i.gpr[0]=0x1800;std::array<uint8_t,32> data{};
 for(unsigned j=0;j<32;j+=sizeof(T)){T a=2,b=3,c=5;auto& d=j<16?i.xmm[0]:i.ymmHigh[0];auto& x=j<16?i.xmm[1]:i.ymmHigh[1];auto& y=j<16?i.xmm[2]:i.ymmHigh[2];std::memcpy(d.data()+j%16,&a,sizeof(T));std::memcpy(x.data()+j%16,&b,sizeof(T));std::memcpy(y.data()+j%16,&c,sizeof(T));std::memcpy(data.data()+j,&c,sizeof(T));}
 assert(m.write(0x1800,data)==GuestMemory64::Fault::none);
 assert(m.write(0x1000,std::array<uint8_t,5>{0xc4,0xe2,uint8_t(0x71|wide|w),uint8_t(order*16+kind),uint8_t(mem?0:0xc2)})==GuestMemory64::Fault::none);
 auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1005);
 for(unsigned j=0;j<32;j+=sizeof(T)){T got;std::memcpy(&got,(j<16?s.xmm[0]:s.ymmHigh[0]).data()+j%16,sizeof(T));T product=order==9?10:order==10?6:15,add=order==9?3:order==10?5:2;bool sub=kind==6?j/sizeof(T)%2==0:kind==7?j/sizeof(T)%2!=0:kind==10||kind==11||kind>=14;T expected=(kind>=12?-product:product)+(sub?-add:add);if(j>=16&&!wide)expected=0;else if(scalar&&j)expected=2;assert(got==expected);}
 ++count;
 };if(w)test.template operator()<double>();else test.template operator()<float>();
 }
 std::cout<<"V63 FMA3 tests passed: "<<count<<" cases\n";
}
