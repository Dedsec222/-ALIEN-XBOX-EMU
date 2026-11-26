#pragma once
#include "guest_memory64.hpp"
#include <array>
#include <cstdint>
namespace genesis {
// Restricted AMD64 unwind decoder: version 1, no handlers/chains, prolog only.
// Body/epilog and frame-register cases deliberately rejected until decoded.
inline bool unwindProlog64(GuestMemory64& m,uint64_t base,uint64_t pc,uint64_t entry,uint64_t context,uint64_t& frame){
 using F=GuestMemory64::Fault;
 auto read=[&](uint64_t a,unsigned n,uint64_t& v){std::array<uint8_t,8>b{};if(m.read(a,std::span<uint8_t>(b).first(n))!=F::none)return false;v=0;for(unsigned i=0;i<n;++i)v|=uint64_t(b[i])<<(8*i);return true;};
 std::array<uint8_t,1232> c{};if(m.read(context,c)!=F::none)return false;
 auto get=[&](unsigned o){uint64_t v=0;for(unsigned i=0;i<8;++i)v|=uint64_t(c[o+i])<<(8*i);return v;};
 auto put=[&](unsigned o,uint64_t v){for(unsigned i=0;i<8;++i)c[o+i]=uint8_t(v>>(8*i));};
 if(!entry){uint64_t sp=get(152),ret;if(sp>UINT64_MAX-8||!read(sp,8,ret))return false;frame=sp;put(152,sp+8);put(248,ret);return m.write(context,c)==F::none;}
 uint64_t begin,end,u,h;if(!read(entry,4,begin)||!read(entry+4,4,end)||!read(entry+8,4,u)||pc<base||pc-base<begin||pc-base>=end||base>UINT64_MAX-u||!read(base+u,4,h))return false;
 unsigned pro=(h>>8)&255,count=(h>>16)&255;uint64_t offset=pc-base-begin;
 if((h&255)!=1||(h>>24)!=0||offset>pro)return false;
 uint64_t sp=get(152);frame=sp;
 auto add=[&](uint64_t n){if(sp>UINT64_MAX-n)return false;sp+=n;return true;};
 auto regok=[](unsigned r){return r==3||r==5||r==6||r==7||r>=12;};
 for(unsigned i=0;i<count;){uint64_t code;if(!read(base+u+4+2*i,2,code))return false;unsigned at=code&255,op=(code>>8)&15,info=code>>12,slots=1;uint64_t n=0;
 if(op==1){slots=info==0?2:info==1?3:0;if(!slots||i+slots>count||!read(base+u+6+2*i,slots==2?2:4,n))return false;if(info==0)n*=8;}
 else if(op==4||op==5){slots=op==4?2:3;if(!regok(info)||i+slots>count||!read(base+u+6+2*i,op==4?2:4,n))return false;if(op==4)n*=8;}
 else if(op==2)n=info*8+8;
 else if(op==0){if(!regok(info))return false;}
 else return false;
 if(at>pro)return false;
 if(at<=offset){if(op==0){uint64_t v;if(!read(sp,8,v)||!add(8))return false;put(120+8*info,v);}else if(op==4||op==5){uint64_t v;if(sp>UINT64_MAX-n||!read(sp+n,8,v))return false;put(120+8*info,v);}else if(!add(n))return false;}
 i+=slots;}
 uint64_t ret;if(!read(sp,8,ret)||!add(8))return false;put(152,sp);put(248,ret);return m.write(context,c)==F::none;
}
}
