#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);unsigned count=0;
for(bool wide:{false,true})for(bool single:{false,true})for(bool mem:{false,true})for(unsigned mode=0;mode<4;++mode)for(unsigned op:{0x2cu,0x2du})for(double v:{-2.5,2.5,0.0,2147483648.0,0x1p63,std::numeric_limits<double>::infinity(),std::numeric_limits<double>::quiet_NaN()}){
Cpu64State i;i.gpr[0]=0x1800;i.mxcsr=0x1f80|(mode<<13);std::array<uint8_t,8> bytes{};if(single){float f=v;std::memcpy(bytes.data(),&f,4);}else std::memcpy(bytes.data(),&v,8);std::memcpy(i.xmm[0].data(),bytes.data(),8);assert(m.write(0x1800,bytes)==GuestMemory64::Fault::none);
assert(m.write(0x1000,std::array<uint8_t,5>{0xc4,0xe1,uint8_t(0x78|(wide?128:0)|(single?2:3)),uint8_t(op),uint8_t(mem?8:0xc8)})==GuestMemory64::Fault::none);
auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1005);unsigned rmode=op==0x2c?3:mode;double r=v;if(v==-2.5)r=rmode==1?-3:-2;if(v==2.5)r=rmode==2?3:2;double lim=wide?0x1p63:0x1p31;bool bad=!std::isfinite(r)||r>=lim||r< -lim;uint64_t expected=bad?(wide?UINT64_C(0x8000000000000000):UINT64_C(0x80000000)):(wide?uint64_t(int64_t(r)):uint64_t(uint32_t(int32_t(r))));assert(s.gpr[1]==expected);assert(bool(s.mxcsr&1)==bad);++count;}
std::cout<<"V73 passed: "<<count<<" cases\n";}
