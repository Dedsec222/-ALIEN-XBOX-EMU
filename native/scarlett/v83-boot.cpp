#include "scarlett_launch.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

int main(int argc,char** argv){
    if(argc!=2)return 1;
    std::ifstream f(argv[1],std::ios::binary);
    if(!f)return 2;
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(f)),
        std::istreambuf_iterator<char>());
    std::cout << genesis::launchScarlett(
        data,1000000000,true,4096,std::filesystem::absolute(argv[1]).parent_path()) << '\n';
}
