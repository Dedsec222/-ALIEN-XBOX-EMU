#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m;ScarlettImports64 h;assert(h.install(m));assert(m.map(0x10000,4096,3)==GuestMemory64::Fault::none);uint64_t r=0;auto call=[&](const char*n,uint64_t b=0){auto p=h.registerImport("api-ms-win-core-interlocked-l1-1-0.dll",n);assert(p&&h.dispatch(p,m,0x10000,r,b));return r;};call("InitializeSListHead");assert(call("InterlockedPushEntrySList",0x10100)==0);assert(call("InterlockedPushEntrySList",0x10110)==0x10100);assert(call("QueryDepthSList")==2);assert(call("InterlockedPopEntrySList")==0x10110);assert(call("InterlockedFlushSList")==0x10100);assert(call("QueryDepthSList")==0);assert(call("InterlockedFlushSList")==0);auto p=h.registerImport("api-ms-win-core-processthreads-l1-1-0.dll","TerminateProcess");assert(p&&h.dispatch(p,m,123,r,9)&&r==0);assert(!h.dispatch(p,m,UINT64_MAX,r,9));std::cout<<"V85E tests passed\n";}
