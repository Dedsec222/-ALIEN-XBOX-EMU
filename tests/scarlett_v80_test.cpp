#include "scarlett_probe.hpp"
#include <cassert>
#include <iostream>
using namespace genesis;
using F=GuestMemory64::Fault;

int main(){
    GuestMemory64 mem;
    assert(mem.map(0x1000,4096,7)==F::none);
    assert(mem.map(0x2000,4096,3)==F::none);

    Cpu64State in{};
    in.gpr[0]=0x123456789abcdef0ULL;
    in.ymmHigh[0].fill(0xab);
    in.xmm[0].fill(0xff);
    in.cf=in.zf=true;

    auto run=[&](std::vector<uint8_t> code){
        assert(mem.write(0x1000,code)==F::none);
        auto out=executeGuest64(mem,0x1000,1,
            in.gpr[4],nullptr,0,0,0,0,&in);
        assert(out.rip==0x1000+code.size());
        assert(out.cf && out.zf);
        assert(out.ymmHigh[0]==in.ymmHigh[0]);
        return out;
    };

    auto a=run({0x66,0x0f,0x6e,0xc0});
    assert(a.xmm[0][0]==0xf0);
    assert(a.xmm[0][3]==0x9a);
    for(unsigned j=4;j<16;++j)
        assert(a.xmm[0][j]==0);

    auto b=run({0x66,0x48,0x0f,0x6e,0xc0});
    assert(b.xmm[0][7]==0x12);
    for(unsigned j=8;j<16;++j)
        assert(b.xmm[0][j]==0);

    in.xmm[0]=b.xmm[0];

    auto c=run({0x66,0x0f,0x7e,0xc1});
    assert(c.gpr[1]==0x9abcdef0ULL);

    auto d=run({0x66,0x48,0x0f,0x7e,0xc1});
    assert(d.gpr[1]==0x123456789abcdef0ULL);

    auto e=run({0xf3,0x0f,0x7e,0xc0});
    assert(e.xmm[0]==b.xmm[0]);

    auto f=run({0x66,0x0f,0xd6,0xc1});
    assert(f.xmm[1]==b.xmm[0]);

    in.gpr[0]=0x2081;
    run({0x66,0x0f,0xd6,0x00});

    auto g=run({0xf3,0x0f,0x7e,0x00});
    assert(g.xmm[0]==b.xmm[0]);

    std::cout<<"V80: 8 SSE2 transfer tests PASSED\n";
}
