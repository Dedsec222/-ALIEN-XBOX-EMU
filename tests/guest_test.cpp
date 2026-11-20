#include "guest.hpp"
#include <cassert>
#include <cstdio>
#include <initializer_list>

using namespace genesis;
static Result run(std::initializer_list<uint8_t> bytes, size_t budget = 32) {
    return interpret({bytes.begin(), bytes.size()}, budget);
}
int main() {
    auto sum = interpret(sum_program, 128);
    assert(sum.stop == Stop::breakpoint && sum.eax == 45 && sum.ecx == 0);
    assert(sum.steps == 30 && sum.rip == sizeof(sum_program));
    assert(run({0xb8, 0xff}).stop == Stop::truncated);
    assert(run({0xff, 0xc0}).stop == Stop::unsupported);
    assert(run({0x90}).stop == Stop::unsupported);
    assert(run({0x75, 0xfd}).stop == Stop::invalidTarget);
    assert(run({0x75, 0}).stop == Stop::invalidTarget);
    auto loop = run({0x75, 0xfe}, 5);
    assert(loop.stop == Stop::budget && loop.steps == 5 && loop.rip == 0);
    auto wrap = run({0xb8,255,255,255,255,0xb9,1,0,0,0,0x01,0xc8,0x75,0x7f,0xcc});
    assert(wrap.stop == Stop::breakpoint && wrap.eax == 0);
    puts("Guest loop passed: EAX=45, ECX=0, 30 instructions. All fault checks passed.");
}
