#pragma once
#include "guest_memory64.hpp"
#include "scarlett_gpu.hpp"
#include <array>
#include <span>
#include <vector>

namespace genesis {

enum class GpuBridgeResult {
    success,
    invalidPacket,
    memoryFault,
    unsupportedOpcode,
    backendFailure
};

template<class Backend>
class ScarlettGpuBridge {
    Backend& gpu;

public:
    static constexpr uint64_t PacketSize=48;
    static constexpr uint64_t MaxCommands=4096;

    uint64_t submissions=0;
    uint64_t executedCommands=0;
    uint64_t rejectedSubmissions=0;

    explicit ScarlettGpuBridge(Backend& backend)
        :gpu(backend){}

    GpuBridgeResult submit(
        const GuestMemory64& memory,
        uint64_t address,
        uint64_t count){

        using R=GpuBridgeResult;
        using Command=ScarlettGpu::Command;
        using Opcode=ScarlettGpu::Opcode;

        auto reject=[&](R result){
            ++rejectedSubmissions;
            return result;
        };

        if(!count || count>MaxCommands ||
           address>UINT64_MAX-count*PacketSize)
            return reject(R::invalidPacket);

        std::vector<Command> commands;
        commands.reserve(count);

        for(uint64_t i=0;i<count;++i){
            std::array<uint8_t,PacketSize> packet{};

            if(memory.read(
                address+i*PacketSize,packet)
                !=GuestMemory64::Fault::none)
                return reject(R::memoryFault);

            auto read=[&](unsigned off,unsigned n){
                uint64_t value=0;
                for(unsigned j=0;j<n;++j)
                    value|=uint64_t(packet[off+j])
                           <<(j*8);
                return value;
            };

            uint64_t op=read(0,4);
            uint32_t pattern=uint32_t(read(4,4));

            Command c{};
            c.src=read(8,8);
            c.dst=read(16,8);
            c.srcOffset=read(24,8);
            c.dstOffset=read(32,8);
            c.size=read(40,8);
            c.pattern=pattern;

            if(!c.dst || !c.size)
                return reject(R::invalidPacket);

            if(op==1){
                c.op=Opcode::fill;

                if(c.src || c.srcOffset ||
                   ((c.dstOffset|c.size)&3))
                    return reject(R::invalidPacket);

            }else if(op==2){
                c.op=Opcode::copy;

                if(!c.src || pattern)
                    return reject(R::invalidPacket);

            }else{
                return reject(R::unsupportedOpcode);
            }

            commands.push_back(c);
        }

        if(!gpu.execute(commands))
            return reject(R::backendFailure);

        ++submissions;
        executedCommands+=count;

        return R::success;
    }
};

}
