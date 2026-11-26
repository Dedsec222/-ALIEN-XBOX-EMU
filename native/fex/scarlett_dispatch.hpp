#pragma once

#include "../scarlett/scarlett_imports64.hpp"
#include <FEXCore/Core/CoreState.h>
#include <stdexcept>
#include <cstdint>

namespace alien {

class ScarlettDispatch {
public:
    genesis::GuestMemory64 memory;
    genesis::ScarlettImports64 imports;

    uint64_t calls = 0;

    bool initialize() {
        return imports.install(memory);
    }

    uint64_t bind(const std::string& dll,
                  const std::string& symbol) {
        return imports.registerImport(dll, symbol);
    }

    uint64_t invoke(
        uint64_t address,
        FEXCore::Core::CpuStateFrame& frame) {

        auto& s = frame.State;
        uint64_t result = s.gregs[0];

        if (!imports.dispatch(
                address,
                memory,
                s.gregs[1],
                result,
                s.gregs[2],
                s.gregs[8],
                s.gregs[9])) {

            throw std::runtime_error(
                "Scarlett import dispatch failed");
        }

        ++calls;
        return result;
    }
};

}
