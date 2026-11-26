#include "scarlett_link64.hpp"
#include <filesystem>
int main(int argc,char**argv){
 if(argc<3)return 1;
 genesis::GuestMemory64 m; genesis::ScarlettImports64 imports;
 if(!imports.install(m)){std::cerr<<"HLE install failed\n";return 3;}
 std::map<std::string,std::filesystem::path> paths;
 std::error_code ec;
 for(const auto& e:std::filesystem::directory_iterator(argv[1],ec)){
  if(!e.is_regular_file())continue;
  auto n=e.path().filename().string();for(auto& c:n)if(c>='A'&&c<='Z')c+=32;
  if(n.ends_with(".dll")&&!paths.emplace(n,e.path()).second){std::cerr<<"Ambiguous DLL: "<<n<<'\n';return 3;}
 }
 if(ec){std::cerr<<ec.message()<<'\n';return 3;}
 genesis::ScarlettLink64 l(m,[&](const std::string& n){auto i=paths.find(n);if(i==paths.end())return std::vector<uint8_t>{};std::ifstream f(i->second,std::ios::binary);return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),{});},[&](const std::string& n,const std::string& s){auto a=imports.registerImport(n,s);std::cout<<(a?"HLE bound: ":"HLE unavailable: ")<<n<<"!"<<s<<'\n';return a;});
 l.exhaustive=std::getenv("ALIEN_LINK_AUDIT")!=nullptr; bool failed=false;
 for(int i=2;i<argc;++i){if(!l.link(argv[i])){std::cerr<<l.error<<'\n';for(auto& s:l.unresolved)std::cerr<<"UNRESOLVED "<<s<<'\n';failed=true;if(!l.exhaustive)return 2;}}
 if(failed)return 2;
 for(auto&[n,v]:l.modules)std::cout<<n<<" mapped 0x"<<std::hex<<v.pe.imageBase<<'\n';
 std::cout<<"Offline linking only; no DLL initialization or execution\n";
}
