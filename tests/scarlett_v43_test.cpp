#include "scarlett_imports64.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
int main(){GuestMemory64 m; ScarlettImports64 i; assert(i.install(m)); assert(m.map(0x1000,4096,3)==GuestMemory64::Fault::none); uint64_t r=0; auto call=[&](const char* n,uint64_t a=0,uint64_t b=0,uint64_t c=0,uint64_t d=0,uint64_t e=0){auto p=i.registerImport("api-ms-win-core-synch-l1-1-0.dll",n);assert(p&&i.dispatch(p,m,a,r,b,c,d,e));return r;}; auto h=call("CreateSemaphoreExW",0,1,2);assert(h);assert(call("WaitForSingleObject",h)==0);assert(call("WaitForSingleObject",h)==258);assert(call("ReleaseSemaphore",h,2,0x1000)==1);assert(call("ReleaseSemaphore",h,1)==0);assert(call("WaitForSingleObject",h)==0);assert(call("WaitForSingleObject",h)==0);assert(call("WaitForSingleObject",h)==258);auto p=i.registerImport("api-ms-win-core-handle-l1-1-0.dll","CloseHandle");assert(i.dispatch(p,m,h,r)&&r==1);assert(call("WaitForSingleObject",h)==UINT32_MAX);std::cout<<"V43 semaphore tests passed\n";}
