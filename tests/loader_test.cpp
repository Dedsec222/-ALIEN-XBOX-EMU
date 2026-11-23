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
    auto metadata = genesis::inspectPe(file);
    assert(!metadata.error);
    assert(metadata.sections >= 1);
    assert(metadata.imageSize > metadata.entryRva);
    assert(metadata.imageBase != 0);
    const auto mapped = genesis::mapPe(file);
    assert(!mapped.error);
    assert(mapped.bytes.size() == metadata.imageSize);
    assert(mapped.entryRva == metadata.entryRva);
    assert(mapped.bytes.at(mapped.entryRva) == image.code[image.entry]);
    for (int door = 1; door <= 3; ++door) {
        for (int target = 1; target <= 3; ++target) {
            auto cpu = genesis::interpret(image.code, 20, image.entry, door, target);
            assert(cpu.stop == genesis::Stop::breakpoint);
            assert(cpu.eax == unsigned(door == target));
            const auto mappedCpu = genesis::interpret(mapped.bytes, 20, mapped.entryRva, door, target);
            assert(mappedCpu.stop == genesis::Stop::breakpoint);
            assert(mappedCpu.eax == cpu.eax);
        }
    }
    for (size_t size = 0; size < file.size(); ++size)
        assert(genesis::loadPe(std::span(file).first(size)).error);
    for (size_t size = 0; size < file.size(); ++size) {
        const auto partial = genesis::inspectPe(std::span(file).first(size));
        if (size < file.size() && !partial.error) {
            // Trailing padding can be omitted without invalidating a PE image.
            assert(size >= 64);
        }
    }
    auto invalid = file;
    invalid[60] = invalid[61] = invalid[62] = invalid[63] = 0xff;
    assert(genesis::loadPe(invalid).error);
    assert(genesis::inspectPe(invalid).error);
    assert(genesis::mapPe(invalid).error);
    file[0] = 0;
    assert(genesis::loadPe(file).error);
    assert(genesis::inspectPe(file).error);
    assert(genesis::mapPe(file).error);
    std::cout << "All nine door/target combinations and truncated files passed.\n";
}
