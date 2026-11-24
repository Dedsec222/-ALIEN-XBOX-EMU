#include "guest_memory64.hpp"
#include <cassert>
#include <cstdio>
using namespace genesis;
int main(){GuestMemory64 m; using F=GuestMemory64::Fault; constexpr uint64_t a=0x800000000000ULL,n=24ULL<<30; assert(m.mapSparse(a,n,3)==F::none); assert(m.sparseCommittedPages()==0); std::array<uint8_t,4> b{1,2,3,4},r{}; assert(m.read(a+n-4,r)==F::none && r[0]==0); assert(m.write(a+4094,b)==F::none); assert(m.sparseCommittedPages()==2); assert(m.read(a+4094,r)==F::none && r==b); assert(m.map(a,4096,3)==F::permission); assert(m.check(a,n,4)==F::permission); assert(m.unmap(a,4096)==F::permission); assert(m.unmap(a,n)==F::none); assert(m.sparseCommittedPages()==0); assert(m.read(a,r)==F::unmapped); puts("V34 sparse memory tests passed");}
