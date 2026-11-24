#include "scarlett_pe64.hpp"
#include "scarlett_cpu64.hpp"
#include <array>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: scarlett-entry-trace <path-to-PE>\n";
        return 2;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) { std::cerr << "Cannot open input PE\n"; return 1; }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
    genesis::GuestMemory64 memory;
    const auto pe=genesis::loadScarlettPe(bytes,memory);
    if (!pe.error.empty()) {
        std::cerr << "PE mapping error: "<<pe.error<<"\n";
        return 1;
    }
    std::array<uint8_t,16> entry{};
    if (memory.read(pe.entry,entry)!=genesis::GuestMemory64::Fault::none ||
        memory.check(pe.entry,entry.size(),genesis::GuestMemory64::Execute)!=
            genesis::GuestMemory64::Fault::none) {
        std::cerr<<"Entry not readable and executable\n";
        return 1;
    }
    std::cout<<"Image base: 0x"<<std::hex<<pe.imageBase
             <<"\nEntry: 0x"<<pe.entry<<"\nEntry bytes:";
    for(auto b:entry) std::cout<<" "<<std::setw(2)<<std::setfill('0')<<unsigned(b);
    std::cout<<"\n";
    // Guest-only bounded execution: no host syscall or native code execution.
    const uint64_t stackBase=0x700000000000ull;
    if(memory.map(stackBase,65536,genesis::GuestMemory64::Read|
        genesis::GuestMemory64::Write)!=genesis::GuestMemory64::Fault::none) {
        std::cerr<<"Cannot map guest stack\\n";return 1;
    }
    const auto state=genesis::executeGuest64(memory,pe.entry,32,stackBase+65536);
    const char* exit="budget";
    switch(state.exit) {
        case genesis::Cpu64Exit::breakpoint: exit="breakpoint";break;
        case genesis::Cpu64Exit::halt: exit="halt";break;
        case genesis::Cpu64Exit::unsupported: exit="unsupported instruction";break;
        case genesis::Cpu64Exit::memoryFault: exit="guest memory fault";break;
        case genesis::Cpu64Exit::budget: break;
    }

    std::array<uint8_t,16> stopBytes{};
    if(memory.read(state.rip,stopBytes)==genesis::GuestMemory64::Fault::none) {
        std::cout<<"Stop bytes:";
        for(auto b:stopBytes)
            std::cout<<" "<<std::hex<<std::setw(2)
                     <<std::setfill('0')<<unsigned(b);
        std::cout<<"\\n";
    }

    if(state.exit==genesis::Cpu64Exit::memoryFault) {
        std::array<uint8_t,6> insn{};
        if(memory.read(state.rip,insn)==
           genesis::GuestMemory64::Fault::none &&
           insn[0]==0xff && insn[1]==0x15) {

            uint32_t raw=0;
            for(unsigned i=0;i<4;++i)
                raw|=uint32_t(insn[2+i])<<(8*i);

            const uint64_t pointerAddress=
                state.rip+6+
                static_cast<uint64_t>(
                    static_cast<int64_t>(
                        static_cast<int32_t>(raw)));

            std::cout<<"Indirect CALL pointer: 0x"
                     <<std::hex<<pointerAddress<<"\\n";

            std::array<uint8_t,8> targetBytes{};
            const auto readResult=
                memory.read(pointerAddress,targetBytes);

            if(readResult!=genesis::GuestMemory64::Fault::none) {
                std::cout<<"Pointer read: FAILED\\n";
            } else {
                uint64_t target=0;
                for(unsigned i=0;i<8;++i)
                    target|=uint64_t(targetBytes[i])<<(8*i);

                std::cout<<"Pointer read: OK\\n";
                std::cout<<"Call target: 0x"
                         <<std::hex<<target<<"\\n";

                const auto checkResult=memory.check(
                    target,1,genesis::GuestMemory64::Execute);

                std::cout<<"Target executable: "
                         <<(checkResult==
                            genesis::GuestMemory64::Fault::none
                            ?"YES":"NO")<<"\\n";
            }
        }
    }

    std::cout<<"Execution exit: "<<exit
             <<"\nStop RIP: 0x"<<std::hex<<state.rip
             <<"\nRAX: 0x"<<state.gpr[0]
             <<"\nRSP: 0x"<<state.gpr[4]
             <<"\nInstructions: "<<std::dec<<state.steps<<"\n";
}
