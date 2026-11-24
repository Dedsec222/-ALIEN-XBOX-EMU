#include "scarlett_cpu64.hpp"
#include <cassert>
#include <chrono>
#include <iostream>
using namespace genesis;
int main(){
    GuestMemory64 memory;
    assert(memory.map(0x1000,4096,7)==GuestMemory64::Fault::none);
    // 64-bit and 32-bit extended registers, write alias, then a backward jump.
    std::vector<uint8_t> code={0x49,0xba,1,2,3,4,5,6,7,8,0x49,0x0f,0xca,0x41,0x0f,0xca,0x90,0xeb,0xed};
    assert(memory.write(0x1000,code)==GuestMemory64::Fault::none);
    Arm64Blocks backend;
    auto run=[&](Arm64Blocks* selected,uint64_t limit,uint64_t stop=0){
        return executeGuest64(memory,0x1000,limit,0x1800,nullptr,0,0,stop,0,nullptr,selected);
    };
    auto same=[](const auto& a,const auto& b){
        assert(a.gpr==b.gpr && a.rip==b.rip && a.steps==b.steps && a.exit==b.exit &&
               a.zf==b.zf && a.sf==b.sf && a.cf==b.cf && a.of==b.of && a.pf==b.pf);
    };
    for(unsigned i=1;i<18;++i)same(run(nullptr,i),run(&backend,i));
    same(run(nullptr,99,0x100a),run(&backend,99,0x100a));
    code[2]=0xfe;
    assert(memory.write(0x1000,code)==GuestMemory64::Fault::none);
    same(run(nullptr,19),run(&backend,19));
    auto start=std::chrono::steady_clock::now();
    auto ref=run(nullptr,100000);
    auto middle=std::chrono::steady_clock::now();
    auto optimized=run(&backend,100000);
    auto end=std::chrono::steady_clock::now();
    same(ref,optimized);
    auto us=[](auto time){return std::chrono::duration_cast<std::chrono::microseconds>(time).count();};
    std::cout<<"100000 guest instructions, interpreter us="<<us(middle-start)
             <<", optional backend us="<<us(end-middle)<<", compiled="<<backend.translations<<", executed blocks="<<backend.calls<<"\n";
#if defined(__aarch64__) && defined(__linux__)
    assert(backend.calls && backend.translations>=2);
#endif
    for(uint8_t ext:{0xe8,0xf0,0xf8}){
        assert(memory.write(0x1000,std::array<uint8_t,3>{0x0f,0xae,ext})==GuestMemory64::Fault::none);
        assert(run(nullptr,1).rip==0x1003);
    }
}
