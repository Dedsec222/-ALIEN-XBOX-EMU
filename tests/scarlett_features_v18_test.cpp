#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m; ScarlettImports64 im; assert(im.install(m));auto f=im.registerImport("api-ms-win-core-processthreads-l1-1-1.dll","IsProcessorFeaturePresent");assert(f && im.contains(f));for(uint64_t id: {0ull,3ull,6ull,10ull,17ull,23ull,28ull,39ull,0xffffffffull}){uint64_t r=99;assert(im.dispatch(f,m,id,r)&&r==0);}assert(!im.registerImport("unknown.dll","IsProcessorFeaturePresent"));std::cout<<"V18 feature tests passed\n";}
