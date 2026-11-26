#pragma once
#include "scarlett_pe64.hpp"
namespace genesis {
// Parse guest export tables without executing or trusting guest code.
struct ScarlettExportTable {
    std::map<std::string,uint64_t> addresses;
    std::map<std::string,std::string> forwarders;
};
inline bool readScarlettExports(GuestMemory64& m,const ScarlettPeResult& p,ScarlettExportTable& out){
    ScarlettExportTable tmp;
    auto read=[&](uint64_t r,unsigned n,uint64_t& v){
        std::array<uint8_t,8>b{};
        if(r>p.imageSize||n>p.imageSize-r||m.read(p.imageBase+r,std::span<uint8_t>(b).first(n))!=GuestMemory64::Fault::none)return false;
        v=0;for(unsigned i=0;i<n;++i)v|=uint64_t(b[i])<<(8*i);return true;
    };
    auto str=[&](uint64_t r,uint64_t end,std::string& v){for(unsigned i=0;i<4096&&r+i<end;++i){uint64_t c;if(!read(r+i,1,c))return false;if(!c)return !v.empty();v+=char(c);}return false;};
    uint64_t h,n,c,d,z;
    if(!read(60,4,h)||!read(h+20,2,n)||n<112||!read(h+132,4,c))return false;
    if(!c){out={};return true;}
    if(n<120||!read(h+136,4,d)||!read(h+140,4,z))return false;
    if(!d&&!z){out={};return true;}
    if(!d||z<40||d>p.imageSize||z>p.imageSize-d)return false;
    uint64_t base,nf,nn,ft,nt,ot;
    if(!read(d+16,4,base)||!read(d+20,4,nf)||!read(d+24,4,nn)||!read(d+28,4,ft)||!read(d+32,4,nt)||!read(d+36,4,ot)||nf>65536||nn>65536)return false;
    auto add=[&](const std::string& key,uint64_t r){if(!r)return true;if(r>=p.imageSize)return false;if(r>=d&&r<d+z){std::string f;if(!str(r,d+z,f))return false;tmp.forwarders[key]=f;}else {if(m.check(p.imageBase+r,1,0)!=GuestMemory64::Fault::none)return false;tmp.addresses[key]=p.imageBase+r;}return true;};
    for(uint64_t i=0;i<nf;++i){uint64_t r;if(!read(ft+4*i,4,r)||!add("#"+std::to_string(base+i),r))return false;}
    for(uint64_t i=0;i<nn;++i){uint64_t a,o,r;std::string key;if(!read(nt+4*i,4,a)||!read(ot+2*i,2,o)||o>=nf||!read(ft+4*o,4,r)||!str(a,p.imageSize,key)||!add(key,r))return false;}
    out=std::move(tmp);return true;
}
}
