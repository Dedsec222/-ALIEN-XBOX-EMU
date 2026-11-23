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
    std::cout<<"Execution exit: "<<exit
             <<"\nStop RIP: 0x"<<std::hex<<state.rip
             <<"\nRAX: 0x"<<state.gpr[0]
             <<"\nRSP: 0x"<<state.gpr[4]
             <<"\nInstructions: "<<std::dec<<state.steps<<"\n";
}
