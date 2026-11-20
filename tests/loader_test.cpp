#include "pe.hpp"
#include <cassert>
#include <fstream>
#include <iterator>
#include <vector>
#include <iostream>

int main() {
    std::ifstream source("app/src/main/assets/doors.exe", std::ios::binary);
    std::vector<uint8_t> file(std::istreambuf_iterator<char>(source), {});
    auto image = genesis::loadPe(file);
    assert(!image.error);
    for (int door = 1; door <= 3; ++door) {
        for (int target = 1; target <= 3; ++target) {
            auto cpu = genesis::interpret(image.code, 20, image.entry, door, target);
            assert(cpu.stop == genesis::Stop::breakpoint);
            assert(cpu.eax == unsigned(door == target));
        }
    }
    for (size_t size = 0; size < file.size(); ++size)
        assert(genesis::loadPe(std::span(file).first(size)).error);
    auto invalid = file;
    invalid[60] = invalid[61] = invalid[62] = invalid[63] = 0xff;
    assert(genesis::loadPe(invalid).error);
    file[0] = 0;
    assert(genesis::loadPe(file).error);
    std::cout << "All nine door/target combinations and truncated files passed.\n";
}
