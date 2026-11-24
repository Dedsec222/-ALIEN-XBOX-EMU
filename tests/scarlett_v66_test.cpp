#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);unsigned count=0;
for(unsigned op:{0x63u,0x67u,0x6bu,0x2bu})for(unsigned wide:{0u,4u})for(bool mem:{false,true}){
 Cpu64State i;i.gpr[0]=0x1800;unsigned w=op==0x63||op==0x67?2:4,n=wide?32:16;bool uns=op==0x67||op==0x2b;
 std::array<uint8_t,32> x{},y{};int32_t vals[]={-100000,-129,-1,0,127,256,32768,100000};
 for(unsigned j=0;j<n/w;++j){int32_t a=vals[j%8],b=vals[(j+3)%8];if(w==2){a=std::clamp(a,-32768,32767);b=std::clamp(b,-32768,32767);}std::memcpy(x.data()+j*w,&a,w);std::memcpy(y.data()+j*w,&b,w);}
 std::memcpy(i.xmm[0].data(),x.data(),16);std::memcpy(i.ymmHigh[0].data(),x.data()+16,16);std::memcpy(i.xmm[2].data(),y.data(),16);std::memcpy(i.ymmHigh[2].data(),y.data()+16,16);
 assert(m.write(0x1800,y)==GuestMemory64::Fault::none);assert(m.write(0x1000,std::array<uint8_t,5>{0xc4,uint8_t(op==0x2b?0xe2:0xe1),uint8_t(0x79|wide),uint8_t(op),uint8_t(mem?8:0xca)})==GuestMemory64::Fault::none);
 auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1005);
 for(unsigned lane=0;lane<n;lane+=16)for(unsigned j=0;j<32/w;++j){auto &v=j<16/w?x:y;int32_t a=0;unsigned off=lane+(j%(16/w))*w;if(w==2){int16_t t;std::memcpy(&t,v.data()+off,2);a=t;}else std::memcpy(&a,v.data()+off,4);a=std::clamp(a,uns?0:w==2?-128:-32768,uns?(w==2?255:65535):(w==2?127:32767));uint16_t got=0;auto &r=lane?s.ymmHigh[1]:s.xmm[1];std::memcpy(&got,r.data()+j*(w/2),w/2);assert(got==(w==2?uint8_t(a):uint16_t(a)));}
 ++count;
}
for(unsigned imm=0;imm<256;++imm)for(bool mem:{false,true}){Cpu64State i;i.gpr[0]=0x1800;i.xmm[0].fill(0x11);i.xmm[2].fill(0x22);i.ymmHigh[1].fill(0xff);assert(m.write(0x1800,i.xmm[2])==GuestMemory64::Fault::none);assert(m.write(0x1000,std::array<uint8_t,6>{0xc4,0xe3,0x79,0x21,uint8_t(mem?8:0xca),uint8_t(imm)})==GuestMemory64::Fault::none);auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1006);for(unsigned j=0;j<16;++j)assert(s.xmm[1][j]==((imm&(1u<<(j/4)))?0:j/4==((imm>>4)&3)?0x22:0x11));for(auto v:s.ymmHigh[1])assert(v==0);++count;}
std::cout<<"V66 tests passed: "<<count<<" cases\n";}
