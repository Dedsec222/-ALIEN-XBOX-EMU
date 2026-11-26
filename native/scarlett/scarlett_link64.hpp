#pragma once
#include "scarlett_module64.hpp"
#include <functional>
#include <set>
namespace genesis {
// Offline linker: mapped modules are NOT initialized or published to the runtime.
class ScarlettLink64 {
public:
 using Provider=std::function<std::vector<uint8_t>(const std::string&)>;
 using Host=std::function<uint64_t(const std::string&,const std::string&)>;
 struct Module { ScarlettPeResult pe; ScarlettExportTable exports; };
 std::map<std::string,Module> modules;
 std::string error;
 bool entrylessOnly=false;
 bool exhaustive=false; std::set<std::string> unresolved;
 ScarlettLink64(GuestMemory64& m,Provider p,Host h={}):mem(m),provider(std::move(p)),host(std::move(h)){}
 bool link(std::string name){error.clear();unresolved.clear();std::vector<std::string> added; auto old=next; if(load(key(name),added)&&unresolved.empty())return true; if(error.empty())error="Unresolved dependencies"; for(auto i=added.rbegin();i!=added.rend();++i){for(auto [a,n]:modules.at(*i).pe.mappings)mem.unmap(a,n);modules.erase(*i);}next=old;return false;}
private:
 GuestMemory64& mem; Provider provider; Host host; uint64_t next=0x20000000000ull;
 static std::string key(std::string s){for(auto& c:s)if(c>='A'&&c<='Z')c+=32;if(s.find('.')==std::string::npos)s+=".dll";return s;}
 bool fail(std::string s){if(error.empty())error=std::move(s);return false;}
 uint64_t symbol(std::string lib,std::string sym,std::vector<std::string>& added,std::set<std::pair<std::string,std::string>>& seen){lib=key(lib);if(seen.size()>=64||!seen.emplace(lib,sym).second)return 0;if(host)if(auto a=host(lib,sym))return a;if(!load(lib,added)){error += " (requested "+lib+"!"+sym+")";return 0;}auto& e=modules.at(lib).exports;if(auto i=e.addresses.find(sym);i!=e.addresses.end())return i->second;if(auto i=e.forwarders.find(sym);i!=e.forwarders.end()){auto p=i->second.rfind('.');if(p!=std::string::npos)return symbol(i->second.substr(0,p),i->second.substr(p+1),added,seen);}return 0;}
 bool load(const std::string& name,std::vector<std::string>& added){if(modules.contains(name))return true;if(modules.size()>=128||name.empty()||name.find_first_of("/\\:")!=std::string::npos||name.find("..")!=std::string::npos)return fail("Invalid module name or module limit");auto bytes=provider(name);if(bytes.empty())return fail("Missing module: "+name);auto p=loadScarlettPe(bytes,mem,next);if(!p.error.empty())return fail(name+": "+p.error);next+=(uint64_t(p.imageSize)+65535)&~65535ull;modules.emplace(name,Module{p,{}});added.push_back(name);if(entrylessOnly && (!p.isDll || p.entry || p.hasTls))return fail("Module requires initialization or is not a DLL: "+name);if(!readScarlettExports(mem,p,modules.at(name).exports))return fail("Invalid exports: "+name);
 auto read=[&](uint64_t r,unsigned n,uint64_t& v){std::array<uint8_t,8>b{};if(r>p.imageSize||n>p.imageSize-r||mem.read(p.imageBase+r,std::span<uint8_t>(b).first(n))!=GuestMemory64::Fault::none)return false;v=0;for(unsigned j=0;j<n;++j)v|=uint64_t(b[j])<<(8*j);return true;};
 auto str=[&](uint64_t r,std::string& s){for(unsigned j=0;j<4096;++j){uint64_t c;if(!read(r+j,1,c))return false;if(!c)return !s.empty();s+=char(c);}return false;};
 uint64_t h,n,c,d,z;if(!read(60,4,h)||!read(h+20,2,n)||n<112||!read(h+132,4,c))return fail("Invalid headers");if(c<2)return true;if(n<128||!read(h+144,4,d)||!read(h+148,4,z))return fail("Invalid import directory");if(!d&&!z)return true;if(!d||z<20||d>p.imageSize||z>p.imageSize-d)return fail("Invalid import bounds");
 for(uint64_t i=d;i+20<=d+z;i+=20){uint64_t oft,t,f,l,iat;if(!read(i,4,oft)||!read(i+4,4,t)||!read(i+8,4,f)||!read(i+12,4,l)||!read(i+16,4,iat))return fail("Invalid descriptor");if(!(oft|t|f|l|iat))return true;std::string lib;if(!iat||!str(l,lib))return fail("Invalid import library");for(uint64_t j=0;;j+=8){uint64_t v,old;if(!read((oft?oft:iat)+j,8,v)||!read(iat+j,8,old))return fail("Invalid thunk");if(!v)break;std::string s;if(v>>63)s="#"+std::to_string(v&65535);else if(v>UINT32_MAX||!str(v+2,s))return fail("Invalid symbol");std::set<std::pair<std::string,std::string>> seen;auto a=symbol(lib,s,added,seen);if(!a){if(!exhaustive)return fail("Unresolved: "+lib+"!"+s);unresolved.insert(lib+"!"+s);error.clear();continue;}std::array<uint8_t,8>b{};for(unsigned k=0;k<8;++k)b[k]=uint8_t(a>>(8*k));if(mem.initialize(p.imageBase+iat+j,b)!=GuestMemory64::Fault::none)return fail("IAT write failed");}}
 return fail("Missing import terminator");}
};
}
