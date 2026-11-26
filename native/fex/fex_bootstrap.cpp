#include "hle_bridge.hpp"
#include <FEXCore/Config/Config.h>
#include <FEXCore/Core/Context.h>
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/Core/HostFeatures.h>
#include <FEXCore/Core/SignalDelegator.h>
#include <FEXCore/Debug/InternalThreadState.h>
#include <FEXCore/HLE/SyscallHandler.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <csetjmp>
#include <cstdlib>
#include <utility>
#include <sys/mman.h>
#include <unistd.h>

using Frame = FEXCore::Core::CpuStateFrame;
using Thread = FEXCore::Core::InternalThreadState;
using Context = FEXCore::Context::Context;
using Syscalls = FEXCore::HLE::SyscallHandler;

static std::jmp_buf ExitPoint;
static Frame* SavedFrame = nullptr;
static bool UnexpectedSyscall = false;

static uint64_t CodeBase = 0;
static uint64_t CodeSize = 0;

[[noreturn]]
static void ExceptionHandler(Context*, Frame* frame) {
    SavedFrame = frame;
    std::longjmp(ExitPoint, 1);
}

class AlienSyscalls final : public Syscalls {
public:
    void HandleSyscall(Frame* frame) override {
        UnexpectedSyscall = true;
        SavedFrame = frame;
        std::longjmp(ExitPoint, 1);
    }

    FEXCore::HLE::ExecutableRangeInfo
    QueryGuestExecutableRange(
        Thread*, uint64_t address) override {

        if (address >= CodeBase &&
            address - CodeBase < CodeSize) {
            return {CodeBase, CodeSize, false};
        }

        return {};
    }

    using SectionResult = decltype(
        std::declval<Syscalls&>()
        .LookupExecutableFileSection(
            nullptr, uint64_t{}));

    SectionResult LookupExecutableFileSection(
        Thread*, uint64_t) override {
        return std::nullopt;
    }
};

int main() {
    const size_t page = sysconf(_SC_PAGESIZE);

    auto* memory = static_cast<uint8_t*>(
        mmap(nullptr, page * 3,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0));

    if (memory == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    auto* code = memory;
    auto* teb = memory + page;
    auto* stack = memory + page * 2;

    CodeBase = reinterpret_cast<uint64_t>(code);
    CodeSize = page;

    // Windows x64 guest program:
    // mov rax, rcx
    // add rax, rdx
    // add rax, r8
    // add rax, r9
    // mov rbx, gs:[0x30]
    // int3

    const uint8_t guest[] = {
        0x48, 0x83, 0xEC, 0x28,
        0xE8, 0x06, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x28,
        0xCC,
        0x90,
        0xCC
    };

    memcpy(code, guest, sizeof(guest));

    const uint64_t tebAddress =
        reinterpret_cast<uint64_t>(teb);

    memcpy(teb + 0x30, &tebAddress, 8);

    if (mprotect(code, page, PROT_READ) != 0) {
        perror("mprotect");
        return 1;
    }

    FEXCore::Config::Initialize();
    FEXCore::Config::Load();
    FEXCore::Config::ReloadMetaLayer();

    FEXCore::Config::Set(
        FEXCore::Config::CONFIG_ENABLECODECACHINGWIP, "0");

    FEXCore::Config::Set(
        FEXCore::Config::CONFIG_IS64BIT_MODE, "1");

    FEXCore::HostFeatures features{};

    features.ProcessFeatures.HostType =
        FEXCore::HostFeatures::HostTypeEnum::Linux;

    features.ProcessFeatures.Is64BitMode = 1;
    features.DCacheLineLog2 = 4;
    features.ProcessPID = getpid();

    // Conservative initial host feature configuration.
    // Advanced ARM extensions remain disabled.

    FEXCore::SignalDelegator signals;
    AlienSyscalls syscalls;

    auto ctx = Context::CreateNewContext(features);

    if (!ctx) {
        puts("Context creation failed");
        return 1;
    }

    ctx->SetSignalDelegator(&signals);
    ctx->SetSyscallHandler(&syscalls);

    if (!ctx->InitCore()) {
        puts("FEXCore initialization failed");
        return 1;
    }

    FEXCore::Core::CPUState initial{};

    initial.rip = CodeBase;
    initial.gs_cached = tebAddress;

    initial.gregs[1] = 10; // RCX
    initial.gregs[2] = 20; // RDX
    initial.gregs[8] = 30; // R8
    initial.gregs[9] = 40; // R9

    initial.gregs[4] =
        reinterpret_cast<uint64_t>(stack + page - 40);

    auto* thread = ctx->CreateThread(&initial);

    if (!thread || !thread->CurrentFrame) {
        puts("Guest thread creation failed");
        return 1;
    }

    using CPUState = FEXCore::Core::CPUState;

    static CPUState::gdt_segment gdt[32]{};
    static CPUState::gdt_segment ldt[8192]{};

    auto& cs = gdt[CPUState::DEFAULT_USER_CS];

    cs.L = 1;
    cs.D = 0;
    cs.P = 1;
    cs.S = 1;
    cs.DPL = 3;
    cs.Type = 0xB;
    cs.G = 1;

    CPUState::SetGDTBase(&cs, 0);
    CPUState::SetGDTLimit(&cs, 0xFFFFF);

    auto& state = thread->CurrentFrame->State;

    state.segment_arrays[
        CPUState::SEGMENT_ARRAY_INDEX_GDT] = gdt;

    state.segment_arrays[
        CPUState::SEGMENT_ARRAY_INDEX_LDT] = ldt;

    state.cs_idx = CPUState::DEFAULT_USER_CS << 3;

    state.gs_cached = tebAddress;


    const size_t callretSize =
        Thread::CALLRET_STACK_SIZE;

    const size_t callretMappingSize =
        callretSize + page * 2;

    auto* callretMapping = static_cast<uint8_t*>(
        mmap(nullptr, callretMappingSize,
             PROT_NONE,
             MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0));

    if (callretMapping == MAP_FAILED) {
        perror("CALLRET mmap");
        return 1;
    }

    auto* callretBase = callretMapping + page;

    if (mprotect(callretBase, callretSize,
                 PROT_READ | PROT_WRITE) != 0) {
        perror("CALLRET mprotect");
        munmap(callretMapping, callretMappingSize);
        return 1;
    }

    thread->CallRetStackBase = callretBase;

    const uint64_t callretTop =
        reinterpret_cast<uint64_t>(
            callretBase + callretSize - 16);

    state.callret_sp = callretTop;

    printf("CALLRET stack initialized: %zu bytes\\n",
           callretSize);

    puts("64-bit guest GDT initialized");

    thread->CurrentFrame->Pointers
        .SynchronousExceptionHandler =
        reinterpret_cast<uintptr_t>(&ExceptionHandler);

    puts("Entering FEXCore guest execution...");
    fflush(stdout);

    if (setjmp(ExitPoint) == 0) {
        ctx->ExecuteThread(thread);
    }

    alien::HLEBridge bridge;

    bridge.thunkAddress = CodeBase + 15;
    bridge.stackBase =
        reinterpret_cast<uint64_t>(stack);
    bridge.stackSize = page;

    bool passed = false;

    if (SavedFrame &&
        !UnexpectedSyscall &&
        SavedFrame->SynchronousFaultData.Signal ==
            FEXCore::Core::FAULT_SIGTRAP &&
        SavedFrame->State.rip == CodeBase + 16 &&
        bridge.dispatch(*SavedFrame)) {


        // Discard cached CALL/RET entries before
        // resuming after a host-emulated return.
        SavedFrame->State.callret_sp = callretTop;

        SavedFrame = nullptr;

        puts("Resuming after HLE import...");
        fflush(stdout);

        if (setjmp(ExitPoint) == 0) {
            ctx->ExecuteThread(thread);
        }

        if (SavedFrame && !UnexpectedSyscall) {
            const auto& state = SavedFrame->State;

            printf("RAX: %llu\\n",
                (unsigned long long)state.gregs[0]);

            printf("HLE calls: %llu\\n",
                (unsigned long long)bridge.calls);

            passed =
                state.gregs[0] == bridge.guestProcessId &&
                state.gregs[4] == initial.gregs[4] &&
                state.rip == CodeBase + 14 &&
                bridge.calls == 1 &&
                SavedFrame->SynchronousFaultData.Signal ==
                    FEXCore::Core::FAULT_SIGTRAP;
        }
    }

    ctx->DestroyThread(thread);
    munmap(callretMapping, callretMappingSize);

    ctx.reset();

    FEXCore::Config::Shutdown();

    munmap(memory, page * 3);

    puts(passed
        ? "FEXCORE HLE IMPORT BRIDGE PASSED"
        : "FEXCORE GUEST EXECUTION FAILED");

    return passed ? 0 : 1;
}
