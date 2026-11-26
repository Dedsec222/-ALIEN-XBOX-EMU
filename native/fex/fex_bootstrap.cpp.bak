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
        0x48, 0x89, 0xC8,
        0x48, 0x01, 0xD0,
        0x4C, 0x01, 0xC0,
        0x4C, 0x01, 0xC8,
        0x65, 0x48, 0x8B, 0x1C,
        0x25, 0x30, 0x00, 0x00, 0x00,
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

    puts("64-bit guest GDT initialized");

    thread->CurrentFrame->Pointers
        .SynchronousExceptionHandler =
        reinterpret_cast<uintptr_t>(&ExceptionHandler);

    puts("Entering FEXCore guest execution...");
    fflush(stdout);

    if (setjmp(ExitPoint) == 0) {
        ctx->ExecuteThread(thread);
    }

    bool passed = false;

    if (SavedFrame && !UnexpectedSyscall) {
        const auto& state = SavedFrame->State;
        const auto& fault = SavedFrame->SynchronousFaultData;

        printf("RAX: %llu\n",
            (unsigned long long)state.gregs[0]);

        printf("RBX: 0x%llx\n",
            (unsigned long long)state.gregs[3]);

        printf("RIP: 0x%llx\n",
            (unsigned long long)state.rip);

        printf("Signal: %u\n", unsigned(fault.Signal));

        passed =
            fault.FaultToTopAndGeneratedException &&
            fault.Signal == FEXCore::Core::FAULT_SIGTRAP &&
            state.gregs[0] == 100 &&
            state.gregs[3] == tebAddress &&
            state.rip == CodeBase + sizeof(guest);
    }

    ctx->DestroyThread(thread);
    ctx.reset();

    FEXCore::Config::Shutdown();

    munmap(memory, page * 3);

    puts(passed
        ? "FEXCORE GUEST EXECUTION PASSED"
        : "FEXCORE GUEST EXECUTION FAILED");

    return passed ? 0 : 1;
}
