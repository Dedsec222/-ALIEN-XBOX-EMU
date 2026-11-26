#include "scarlett_imports64.hpp"
#include <iostream>
int main(){genesis::GuestMemory64 m;genesis::ScarlettImports64 h;if(!h.install(m))return 1;std::string line;while(std::getline(std::cin,line)){auto p=line.find('\t');if(p==std::string::npos)continue;auto a=h.registerImport(line.substr(0,p),line.substr(p+1));std::cout<<(a?"BOUND_EXPERIMENTAL":"UNBOUND")<<'\t'<<line<<'\n';}}
