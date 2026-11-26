#pragma once

#include <FEXCore/Core/CoreState.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <unistd.h>

namespace alien {

using Frame = FEXCore::Core::CpuStateFrame;

class HLEBridge {
public:
    uint64_t thunkAddress = 0;
    uint64_t stackBase = 0;
    uint64_t stackSize = 0;
    uint32_t guestProcessId = 1000;
    uint64_t calls = 0;

    bool dispatch(Frame& frame) {
        auto& state = frame.State;

        if (state.rip == 0 ||
            state.rip - 1 != thunkAddress)
            return false;

        const uint64_t rsp = state.gregs[4];

        if (stackSize < 8 ||
            rsp < stackBase ||
            rsp - stackBase > stackSize - 8)
            return false;

        uint64_t returnAddress = 0;

        std::memcpy(
            &returnAddress,
            reinterpret_cast<const void*>(rsp),
            sizeof(returnAddress));

        if (!returnAddress)
            return false;

        // GetCurrentProcessId:
        // Return the emulated process identifier.
        state.gregs[0] = guestProcessId;

        // Emulate the guest RET instruction.
        state.gregs[4] = rsp + 8;
        state.rip = returnAddress;

        frame.SynchronousFaultData = {};

        ++calls;

        std::printf(
            "[HLE] GetCurrentProcessId -> %u\n",
            guestProcessId);

        return true;
    }
};

}
