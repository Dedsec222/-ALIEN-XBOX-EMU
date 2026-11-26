#pragma once

#include "../scarlett/scarlett_imports64.hpp"
#include <FEXCore/Core/CoreState.h>
#include <stdexcept>
#include <cstdint>
#include <array>

namespace alien {

class ScarlettDispatch {
public:
    genesis::GuestMemory64 memory;
    genesis::ScarlettImports64 imports;

    uint64_t calls = 0;
    uint64_t stackBase = 0;
    uint64_t stackSize = 0;

    bool initialize() {
        
        if(!memory.enableDirectHeap())
            return false;

        if(!imports.enableNativeHeap())
            return false;

        
        if(!memory.enableDirectVirtual())
            return false;

        if(!imports.enableNativeVirtual())
            return false;

        
        if(!memory.enableDirectSparse())
            return false;

        imports.enableNativeXboxMemory();

        imports.enableNativeCrt();

        return imports.install(memory);



    }

    uint64_t bind(const std::string& dll,
                  const std::string& symbol) {
        return imports.registerImport(dll, symbol);
    }

    uint64_t stackArgument(
        uint64_t rsp, unsigned index) const {

        const uint64_t offset =
            0x28 + uint64_t(index) * 8;

        if (rsp > UINT64_MAX - offset)
            throw std::runtime_error(
                "Stack address overflow");

        const uint64_t address = rsp + offset;

        if (stackSize < 8 ||
            address < stackBase ||
            address - stackBase > stackSize - 8)
            throw std::runtime_error(
                "Stack argument outside mapping");

        uint64_t value = 0;

        std::memcpy(
            &value,
            reinterpret_cast<const void*>(address),
            sizeof(value));

        return value;
    }

    uint64_t invoke(
        uint64_t address,
        FEXCore::Core::CpuStateFrame& frame) {

        auto& s = frame.State;
        uint64_t result = s.gregs[0];

        const uint64_t rsp = s.gregs[4];

        const uint64_t arg5 = stackArgument(rsp,0);
        const uint64_t arg6 = stackArgument(rsp,1);
        const uint64_t arg7 = stackArgument(rsp,2);
        const uint64_t arg8 = stackArgument(rsp,3);

        if (!imports.dispatch(
                address,
                memory,
                s.gregs[1],
                result,
                s.gregs[2],
                s.gregs[8],
                s.gregs[9],
                arg5,
                arg6,
                nullptr,
                arg7,
                arg8)) {

            throw std::runtime_error(
                "Scarlett import dispatch failed");
        }

        ++calls;
        return result;
    }
};

}
