#pragma once

#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <unordered_map>
#include <functional>
#include <string>
#include <utility>

namespace alien {

using Frame = FEXCore::Core::CpuStateFrame;

class HLEBridge {
public:
    using Handler = std::function<uint64_t(Frame&)>;

    uint64_t stackBase = 0;
    uint64_t stackSize = 0;
    uint64_t codeBase = 0;
    uint64_t codeSize = 0;

    std::function<bool(uint64_t)>
        executableAddress;


    uint32_t guestProcessId = 1000;
    uint32_t guestThreadId = 1001;
    uint64_t calls = 0;

    struct Entry {
        std::string name;
        Handler handler;
    };

    std::unordered_map<uint64_t, Entry> registry;

    bool bind(uint64_t address,
              std::string name,
              Handler handler) {
        if (!address || !handler)
            return false;

        return registry.emplace(
            address,
            Entry{std::move(name),
                  std::move(handler)}
        ).second;
    }

    bool dispatch(Frame& frame) {
        auto& state = frame.State;

        if (!state.rip ||
            frame.SynchronousFaultData.Signal !=
                FEXCore::Core::FAULT_SIGTRAP)
            return false;

        auto it = registry.find(state.rip - 1);

        if (it == registry.end())
            return false;

        const uint64_t rsp = state.gregs[4];

        if (stackSize < 8 ||
            rsp < stackBase ||
            rsp - stackBase > stackSize - 8)
            return false;

        uint64_t ret = 0;

        std::memcpy(
            &ret,
            reinterpret_cast<const void*>(rsp),
            sizeof(ret));


        if(executableAddress){

            if(!executableAddress(ret))
                return false;

        }else if(ret<codeBase ||
                 ret-codeBase>=codeSize){

            return false;
        }


        state.gregs[0] = it->second.handler(frame);
        state.gregs[4] = rsp + 8;
        state.rip = ret;

        frame.SynchronousFaultData = {};

        ++calls;

        std::printf("[HLE] %s -> 0x%llx\n",
            it->second.name.c_str(),
            (unsigned long long)state.gregs[0]);

        return true;
    }
};

}
