#include "scarlett_shader.hpp"
#include <cassert>
#include <fstream>
int main(int argc,char** argv){
    using namespace genesis;
    auto shader=greenPixel;
    auto module=translateConstantPixel(shader);
    assert(!module.empty());
    shader[10]=0xbf000000;
    assert(module!=translateConstantPixel(shader));
    shader[5]^=1;
    assert(translateConstantPixel(shader).empty());
    assert(translateConstantPixel(std::span(greenPixel).first(13)).empty());
    if(argc==2){
        std::ofstream file(argv[1],std::ios::binary);
        file.write(reinterpret_cast<const char*>(module.data()),module.size()*4);
        return !file;
    }
}
