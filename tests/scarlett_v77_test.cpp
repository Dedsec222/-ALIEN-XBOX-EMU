#include "scarlett_cpu64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){
 GuestMemory64 m; assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);
 unsigned total=0;
 for(unsigned n:{1u,2u,4u,8u}) for(unsigned g=0;g<4;++g) for(unsigned mode=0;mode<3;++mode) for(bool mem:{false,true}) for(bool carry:{false,true}) for(unsigned c:{0u,1u,7u,8u,9u,16u,17u,31u,32u,63u,64u,255u}) {
  unsigned bits=n*8; uint64_t mask=~uint64_t(0)>>(64-bits),v=0xa5b6c7d8e9fa1235ull&mask; Cpu64State i; i.gpr[0]=mem?0x1800:v;i.gpr[1]=c;i.cf=carry;i.zf=true;i.pf=true;i.sf=true;
  std::vector<uint8_t> code; if(n==2)code.push_back(0x66);if(n==8)code.push_back(0x48);
  code.push_back(uint8_t((mode==0?0xd0:mode==1?0xd2:0xc0)+(n!=1)));code.push_back(uint8_t((mem?0:0xc0)|(g<<3)));if(mode==2)code.push_back(uint8_t(c));
  assert(m.write(0x1000,code)==GuestMemory64::Fault::none);assert(m.write(0x1800,std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&v),n))==GuestMemory64::Fault::none);
  auto s=executeGuest64(m,0x1000,1,0x1900,nullptr,0,0,0,0,&i);assert(s.rip==0x1000+code.size());
  unsigned k=(mode==0?1:c)&(bits==64?63:31),width=bits+(g>=2);unsigned shift=k%width;using U=__uint128_t;U x=v;if(g>=2)x|=U(carry)<<bits;U full=(U(1)<<width)-1;
  if(shift)x=(g%2?((x>>shift)|(x<<(width-shift))):((x<<shift)|(x>>(width-shift))))&full;
  uint64_t expected=uint64_t(x)&mask,actual=s.gpr[0]&mask;if(mem){actual=0;assert(m.read(0x1800,std::span<uint8_t>(reinterpret_cast<uint8_t*>(&actual),n))==GuestMemory64::Fault::none);}assert(actual==expected);assert(s.zf&&s.pf&&s.sf);
  bool cf=carry;if(k && (g<2||shift))cf=g>=2?bool(x>>bits):g==0?bool(x&1):bool(x>>(bits-1));assert(s.cf==cf);++total;
 }
 ScarlettImports64 imports;assert(imports.install(m));auto a=imports.registerImport("api-ms-win-crt-math-l1-1-0.dll","_dtest");assert(a);for(double v:{0.0,1.0,std::numeric_limits<double>::denorm_min(),std::numeric_limits<double>::infinity(),std::numeric_limits<double>::quiet_NaN()}){assert(m.write(0x1800,std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&v),8))==GuestMemory64::Fault::none);uint64_t r=0;assert(imports.dispatch(a,m,0x1800,r));assert(r==uint16_t(std::isnan(v)?2:std::isinf(v)?1:v==0?0:std::fpclassify(v)==FP_SUBNORMAL?-2:-1));++total;}
 std::cout<<"V77 passed: "<<total<<" cases\n";
}
