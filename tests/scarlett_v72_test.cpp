#include "scarlett_cpu64.hpp"
#include <cassert>
#include <vector>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;assert(m.map(0x1000,4096,7)==GuestMemory64::Fault::none);unsigned count=0;
for(unsigned prefix=0;prefix<5;++prefix)for(unsigned mod=0;mod<4;++mod)for(unsigned rm=0;rm<8;++rm)for(unsigned base=0;base<8;++base){std::vector<uint8_t> c;for(unsigned i=0;i<prefix;++i)c.push_back(0x66);c.insert(c.end(),{0x0f,0x1f,uint8_t(mod*64+rm)});if(mod!=3&&rm==4)c.push_back(uint8_t(base));unsigned n=mod==1?1:mod==2?4:mod==0&&(rm==5||(rm==4&&base==5))?4:0;while(n--)c.push_back(0xff);assert(m.write(0x1000,c)==GuestMemory64::Fault::none);Cpu64State i;i.gpr.fill(0xffffffffffffffffull);i.cf=i.zf=true;auto s=executeGuest64(m,0x1000,1,i.gpr[4],nullptr,0,0,0,0,&i);assert(s.rip==0x1000+c.size()&&s.steps==1&&s.gpr==i.gpr&&s.cf&&s.zf);++count;}
std::cout<<"V72 NOP tests passed: "<<count<<" cases\n";}
