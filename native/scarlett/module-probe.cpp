#include "scarlett_module64.hpp"
#include <fstream>
int main(int argc,char**argv){if(argc!=2)return 1;std::ifstream f(argv[1],std::ios::binary);if(!f)return 2;std::vector<uint8_t>b((std::istreambuf_iterator<char>(f)),{});genesis::GuestMemory64 m;auto p=genesis::loadScarlettPe(b,m);if(!p.error.empty()){std::cerr<<p.error<<'\n';return 3;}genesis::ScarlettExportTable e;if(!genesis::readScarlettExports(m,p,e))return 4;for(auto&[k,v]:e.addresses)std::cout<<k<<" 0x"<<std::hex<<v<<'\n';for(auto&[k,v]:e.forwarders)std::cout<<k<<" -> "<<v<<'\n';}
