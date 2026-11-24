#include "scarlett_imports64.hpp"
#include <iostream>
#include <sstream>
// Input rows: IAT DLL symbol, as exported by a PE inventory.
int main(){
    genesis::ScarlettImports64 imports;
    genesis::GuestMemory64 memory;
    if (!imports.install(memory)) return 1;
    std::cout<<"iat,dll,symbol,status,stub\n";
    std::string line;
    while (std::getline(std::cin,line)) {
        std::istringstream row(line);
        std::string iat,dll,symbol;
        if (!(row>>iat>>dll>>symbol) || !iat.starts_with("0x")) continue;
        const auto stub=imports.registerImport(dll,symbol);
        std::string status="unsupported";
        if (stub) {
            status="partial";
            if(symbol=="OutputDebugStringA") status="safely optional";
            if(symbol=="htons" || symbol=="ntohs" || symbol=="htonl" || symbol=="ntohl" ||
               symbol=="GetLastError" || symbol=="SetLastError") status="implemented";
        }
        std::cout<<iat<<','<<dll<<",\"";
        for(char ch:symbol){if(ch=='"')std::cout<<'"';std::cout<<ch;}
        std::cout<<"\","<<status<<",0x"<<std::hex<<stub<<'\n';
    }
}
