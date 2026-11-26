#include "shared_runtime_memory.hpp"
#include "scarlett_dispatch.hpp"
#include "scarlett_memory_adapter.hpp"
#include <exception>
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

static uint64_t HLECodeBase = 0;
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
            address - CodeBase < CodeSize)
            return {CodeBase, CodeSize, false};

        if (address >= HLECodeBase &&
            address - HLECodeBase < CodeSize)
            return {HLECodeBase, CodeSize, false};

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
        mmap(nullptr, page * 4,
             PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0));

    if (memory == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    auto* code = memory;
    auto* teb = memory + page;
    auto* stack = memory + page * 3;

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
        0x48, 0x83, 0xEC, 0x48,
        0xFF, 0x15, 0xF6, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xC3,
        0xFF, 0x15, 0xF5, 0x00, 0x00, 0x00,
        0x48, 0x01, 0xC3,
        0xFF, 0x15, 0xF4, 0x00, 0x00, 0x00,
        0x48, 0x01, 0xD8,
        0x48, 0x83, 0xC4, 0x48,
        
    // mov r10, [r12]
    0x4D,0x8B,0x14,0x24,

    // mov [r13], r10
    0x4D,0x89,0x55,0x00,

    // mov r11, [r13]
    0x4D,0x8B,0x5D,0x00,

    // mov [r12+8], r11
    0x4D,0x89,0x5C,0x24,0x08,

    
    // mov r10, [r14]
    0x4D,0x8B,0x16,

    // mov [r15], r10
    0x4D,0x89,0x17,

    
    // mov r10, 0x4000000000
    0x49,0xBA,0x00,0x00,0x00,0x00,
    0x40,0x00,0x00,0x00,

    // mov ecx, [r10+8] (argc)
    0x41,0x8B,0x4A,0x08,

    // mov rdx, [r10+16] (argv)
    0x49,0x8B,0x52,0x10,

    // mov rdx, [rdx] (argv[0])
    0x48,0x8B,0x12,

    // movzx r8d, byte ptr [rdx]
    0x44,0x0F,0xB6,0x02,

    // mov dword ptr [r10], 0x12345678
    0x41,0xC7,0x02,0x78,0x56,0x34,0x12,

    
    // mov rbx, gs:[0x30]
    0x65,0x48,0x8B,0x1C,0x25,
    0x30,0x00,0x00,0x00,

    // mov rsi, gs:[0x40]
    0x65,0x48,0x8B,0x34,0x25,
    0x40,0x00,0x00,0x00,

    // mov rdi, gs:[0x48]
    0x65,0x48,0x8B,0x3C,0x25,
    0x48,0x00,0x00,0x00,

    // mov r10, gs:[0x08]
    0x65,0x4C,0x8B,0x14,0x25,
    0x08,0x00,0x00,0x00,

    // mov r11, gs:[0x10]
    0x65,0x4C,0x8B,0x1C,0x25,
    0x10,0x00,0x00,0x00,

    // mov qword ptr gs:[0x1480], 0x12345678
    0x65,0x48,0xC7,0x04,0x25,
    0x80,0x14,0x00,0x00,
    0x78,0x56,0x34,0x12,

    
    // mov r9d, gs:[0x68]
    0x65,0x44,0x8B,0x0C,0x25,
    0x68,0x00,0x00,0x00,

    // mov dword ptr gs:[0x68], 0x5678
    0x65,0xC7,0x04,0x25,
    0x68,0x00,0x00,0x00,
    0x78,0x56,0x00,0x00,

    0xCC
    };

    memcpy(code, guest, sizeof(guest));

    alien::ScarlettDispatch runtime;
    runtime.stackBase =
        reinterpret_cast<uint64_t>(stack);
    runtime.stackSize = page;


    if (!runtime.initialize()) {
        puts("Scarlett initialization failed");
        return 1;
    }

    const char* dll =
        "api-ms-win-core-processthreads-l1-1-0.dll";

    const char* names[] = {
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetCurrentProcess"
    };

    uint64_t bindings[3]{};

    for (unsigned i = 0; i < 3; ++i) {
        bindings[i] = runtime.bind(dll, names[i]);

        if (!bindings[i]) {
            printf("Unresolved: %s\n", names[i]);
            return 1;
        }

        code[0x200 + i * 16] = 0xCC;
    }

    alien::Pe64Image pe;

    pe.image_base = 0x180000000ULL;
    pe.image_size = page * 3;
    pe.header_size = page;
    pe.entry_rva = page;
    pe.image.resize(pe.image_size);

    pe.sections.push_back({
        ".text", uint32_t(page),
        uint32_t(page), 0, 0, 0x60000000u
    });

    pe.sections.push_back({
        ".idata", uint32_t(page * 2),
        uint32_t(page), 0, 0, 0xc0000000u
    });

    // Copy guest instructions into the PE image.
    memcpy(pe.image.data() + page,
           guest, sizeof(guest));

    // Rewrite RIP-relative CALL displacements.
    const unsigned callOffsets[] = {4,13,22};

    for (unsigned i = 0; i < 3; ++i) {
        const uint32_t slot = page * 2 + i * 8;

        const int32_t displacement =
            int32_t(slot) -
            int32_t(page + callOffsets[i] + 6);

        memcpy(pe.image.data() + page +
               callOffsets[i] + 2,
               &displacement, 4);

        pe.imports.push_back({
            dll, names[i], 0, false, slot
        });
    }

    const uint64_t thunkBase = CodeBase;
    HLECodeBase = thunkBase;

    alien::DirectPeLoader loader;

    loader.load(std::move(pe), 0,
        [&](const alien::PeImport& imp)
            -> std::optional<uint64_t> {

            for (unsigned i = 0; i < 3; ++i) {
                if (imp.module == dll &&
                    imp.symbol == names[i])
                    return thunkBase + 0x200 + i * 16;
            }

            return std::nullopt;
        });

    
    alien::connectRuntimeMemory(
        runtime.memory, loader,
        reinterpret_cast<uint64_t>(stack), page,
        reinterpret_cast<uint64_t>(teb), page * 2);

    using Fault = genesis::GuestMemory64::Fault;

    const uint64_t stackAddress =
        reinterpret_cast<uint64_t>(stack);

    const uint64_t tebTestAddress =
        reinterpret_cast<uint64_t>(teb) + 0x100;

    std::array<uint8_t,8> pattern{
        0x88,0x77,0x66,0x55,
        0x44,0x33,0x22,0x11
    };

    for (uint64_t address :
            {stackAddress, tebTestAddress}) {

        if (runtime.memory.write(address,pattern)
                != Fault::none)
            return 1;

        uint64_t actual = 0;

        memcpy(&actual,
               reinterpret_cast<void*>(address),8);

        if (actual != 0x1122334455667788ULL)
            return 1;

        actual = 0x8877665544332211ULL;

        memcpy(reinterpret_cast<void*>(address),
               &actual,8);

        std::array<uint8_t,8> output{};

        if (runtime.memory.read(address,output)
                != Fault::none ||
            output[0] != 0x11 ||
            output[7] != 0x88)
            return 1;

        if (runtime.memory.check(address,1,4)
                != Fault::permission)
            return 1;

        memset(reinterpret_cast<void*>(address),0,8);
    }

    puts("SHARED STACK MEMORY PASSED");
    puts("SHARED TEB MEMORY PASSED");

    {
        const char* heapDll =
            "api-ms-win-crt-heap-l1-1-0.dll";

        auto mallocStub=runtime.bind(heapDll,"malloc");
        auto callocStub=runtime.bind(heapDll,"calloc");
        auto reallocStub=runtime.bind(heapDll,"realloc");
        auto freeStub=runtime.bind(heapDll,"free");

        if(!mallocStub || !callocStub ||
           !reallocStub || !freeStub)
            return 1;

        uint64_t ptr=0;

        if(!runtime.imports.dispatch(
            mallocStub,runtime.memory,4096,ptr))
            return 1;

        if(!ptr ||
           ptr<genesis::GuestMemory64::DirectHeapBase ||
           ptr>=genesis::GuestMemory64::DirectHeapLimit)
            return 1;

        const uint64_t magic=0x1122334455667788ULL;

        memcpy(reinterpret_cast<void*>(ptr),&magic,8);

        std::array<uint8_t,8> bytes{};

        if(runtime.memory.read(ptr,bytes)!=Fault::none)
            return 1;

        uint64_t actual=0;
        memcpy(&actual,bytes.data(),8);

        if(actual!=magic)
            return 1;

        puts("NATIVE MALLOC SHARED ACCESS PASSED");

        uint64_t resized=0;

        if(!runtime.imports.dispatch(
            reallocStub,runtime.memory,
            ptr,resized,8192) || !resized)
            return 1;

        actual=0;
        memcpy(&actual,
            reinterpret_cast<const void*>(resized),8);

        if(actual!=magic)
            return 1;

        puts("NATIVE REALLOC PRESERVATION PASSED");

        uint64_t zero=0;

        if(!runtime.imports.dispatch(
            callocStub,runtime.memory,16,zero,32)
            || !zero)
            return 1;

        for(unsigned i=0;i<512;++i)
            if(reinterpret_cast<const uint8_t*>(zero)[i])
                return 1;

        puts("NATIVE CALLOC ZEROING PASSED");

        uint64_t ignored=0;

        if(!runtime.imports.dispatch(
            freeStub,runtime.memory,resized,ignored))
            return 1;

        if(!runtime.imports.dispatch(
            freeStub,runtime.memory,zero,ignored))
            return 1;

        if(runtime.memory.directHeapCount()!=0)
            return 1;

        if(runtime.memory.check(
            resized,1,genesis::GuestMemory64::Read)
            !=Fault::unmapped)
            return 1;

        puts("NATIVE FREE AND CLEANUP PASSED");

        const char* vmDll=
            "api-ms-win-core-memory-l1-1-0.dll";

        auto alloc=runtime.bind(vmDll,"VirtualAlloc");
        auto release=runtime.bind(vmDll,"VirtualFree");
        auto protect=runtime.bind(vmDll,"VirtualProtect");

        if(!alloc || !release || !protect)
            return 1;

        uint64_t base=0;

        if(!runtime.imports.dispatch(
            alloc,runtime.memory,
            0,base,65536,0x2000,4) || !base)
            return 1;

        if(runtime.memory.check(base,1,1)
            !=Fault::unmapped)
            return 1;

        puts("NATIVE VIRTUAL RESERVE PASSED");

        uint64_t result=0;

        if(!runtime.imports.dispatch(
            alloc,runtime.memory,
            base,result,8192,0x1000,4)
            || result!=base)
            return 1;

        const uint64_t vmMagic=0x123456789abcdef0ULL;

        memcpy(reinterpret_cast<void*>(base),
               &vmMagic,8);

        std::array<uint8_t,8> vmBytes{};

        if(runtime.memory.read(base,vmBytes)
            !=Fault::none)
            return 1;

        uint64_t vmActual=0;
        memcpy(&vmActual,vmBytes.data(),8);

        if(vmActual!=vmMagic)
            return 1;

        puts("NATIVE VIRTUAL COMMIT PASSED");

        uint64_t oldPtr=
            reinterpret_cast<uint64_t>(stack)+0x100;

        if(!runtime.imports.dispatch(
            protect,runtime.memory,
            base,result,4096,2,oldPtr)
            || result!=1)
            return 1;

        uint32_t oldProtection=0;

        memcpy(&oldProtection,
            reinterpret_cast<const void*>(oldPtr),4);

        if(oldProtection!=4 ||
           runtime.memory.write(base,vmBytes)
               !=Fault::permission)
            return 1;

        puts("NATIVE VIRTUAL PROTECT PASSED");

        if(!runtime.imports.dispatch(
            release,runtime.memory,
            base,result,8192,0x4000)
            || result!=1)
            return 1;

        if(runtime.memory.check(base,1,1)
            !=Fault::unmapped)
            return 1;

        puts("NATIVE VIRTUAL DECOMMIT PASSED");

        if(!runtime.imports.dispatch(
            alloc,runtime.memory,
            base,result,8192,0x1000,4)
            || result!=base)
            return 1;

        vmActual=1;

        memcpy(&vmActual,
            reinterpret_cast<const void*>(base),8);

        if(vmActual!=0)
            return 1;

        puts("NATIVE VIRTUAL RECOMMIT ZEROING PASSED");

        if(!runtime.imports.dispatch(
            release,runtime.memory,
            base,result,0,0x8000)
            || result!=1)
            return 1;

        if(runtime.memory.nativeReservationCount()!=0 ||
           runtime.memory.reservationCommittedPages()!=0)
            return 1;

        puts("NATIVE VIRTUAL RELEASE PASSED");

    }



    printf("PE imports resolved: %zu\n",
           size_t(loader.imports().resolved));

    if (loader.imports().resolved != 3 ||
        !loader.imports().unresolved.empty())
        return 1;

    CodeBase = loader.entry();
    CodeSize = page;

    const uint64_t tebAddress =
        reinterpret_cast<uint64_t>(teb);

    
    auto tebPut64=[&](size_t offset,uint64_t value){
        memcpy(teb+offset,&value,8);
    };

    auto tebPut32=[&](size_t offset,uint32_t value){
        memcpy(teb+offset,&value,4);
    };

    tebPut64(0x00,UINT64_MAX);
    tebPut64(0x08,
        reinterpret_cast<uint64_t>(stack+page));
    tebPut64(0x10,
        reinterpret_cast<uint64_t>(stack));

    tebPut64(0x30,tebAddress);

    // CLIENT_ID
    tebPut64(0x40,1000);
    tebPut64(0x48,1);

    // LastErrorValue
    tebPut32(0x68,0);

    // Initial TLS slots.
    memset(teb+0x1480,0,64*8);

    runtime.imports.selectThread(1,tebAddress);


    constexpr uint64_t tlsNative=0x1FFFFF0000ULL;

    if(runtime.memory.reserve(tlsNative,8192)
        !=genesis::GuestMemory64::Fault::none)
        return 1;

    if(runtime.memory.commit(tlsNative,8192,3)
        !=genesis::GuestMemory64::Fault::none)
        return 1;

    tebPut64(0x1780,tlsNative);

    runtime.imports.enableNativeTls();

    const char* tlsDll=
        "api-ms-win-core-processthreads-l1-1-0.dll";

    const auto tlsAlloc=runtime.bind(tlsDll,"TlsAlloc");
    const auto tlsFree=runtime.bind(tlsDll,"TlsFree");
    const auto tlsGet=runtime.bind(tlsDll,"TlsGetValue");
    const auto tlsSet=runtime.bind(tlsDll,"TlsSetValue");

    if(!tlsAlloc || !tlsFree || !tlsGet || !tlsSet)
        return 1;

    auto tlsCall=[&](uint64_t api,uint64_t a,
                     uint64_t b,uint64_t& result){
        return runtime.imports.dispatch(
            api,runtime.memory,a,result,b);
    };

    uint64_t tlsResult=0;

    for(uint32_t i=0;i<1088;++i){
        if(!tlsCall(tlsAlloc,0,0,tlsResult)
           || tlsResult!=i)
            return 1;

        if(!tlsCall(tlsSet,i,0xA1100000ULL+i,tlsResult)
           || tlsResult!=1)
            return 1;
    }

    puts("ALL 1088 NATIVE TLS INDICES ALLOCATED");

    if(!tlsCall(tlsAlloc,0,0,tlsResult)
       || tlsResult!=UINT32_MAX)
        return 1;

    puts("TLS EXHAUSTION HANDLING PASSED");

    for(uint32_t i=0;i<1088;++i){
        if(!tlsCall(tlsGet,i,0,tlsResult)
           || tlsResult!=0xA1100000ULL+i)
            return 1;
    }

    puts("ALL NATIVE TLS VALUES VERIFIED");

    for(uint32_t i=0;i<1088;++i){
        if(!tlsCall(tlsFree,i,0,tlsResult)
           || tlsResult!=1)
            return 1;
    }

    if(!tlsCall(tlsAlloc,0,0,tlsResult)
       || tlsResult!=0)
        return 1;

    if(!tlsCall(tlsGet,0,0,tlsResult)
       || tlsResult!=0)
        return 1;

    puts("TLS SLOT REUSE AND ZEROING PASSED");

    const char* errorDll=
        "api-ms-win-core-errorhandling-l1-1-0.dll";

    const auto errorSet=
        runtime.bind(errorDll,"SetLastError");

    const auto errorGet=
        runtime.bind(errorDll,"GetLastError");

    if(!errorSet || !errorGet)
        return 1;

    auto errorCall=[&](uint64_t api,uint64_t arg,
                       uint64_t& result){
        return runtime.imports.syncLastErrorFromTeb(
                   runtime.memory) &&
               runtime.imports.dispatch(
                   api,runtime.memory,arg,result) &&
               runtime.imports.syncLastErrorToTeb(
                   runtime.memory);
    };

    uint64_t errorResult=0;
    uint32_t nativeError=0;

    if(!errorCall(errorSet,0x1234,errorResult))
        return 1;

    memcpy(&nativeError,teb+0x68,4);

    if(nativeError!=0x1234)
        return 1;

    puts("SETLASTERROR TO NATIVE TEB PASSED");

    if(!errorCall(errorGet,0,errorResult)
       || errorResult!=0x1234)
        return 1;

    puts("GETLASTERROR PRESERVATION PASSED");

    if(!errorCall(tlsGet,9999,errorResult)
       || errorResult!=0)
        return 1;

    memcpy(&nativeError,teb+0x68,4);

    if(nativeError!=87)
        return 1;

    puts("TLS FAILURE LASTERROR PROPAGATION PASSED");

    if(!errorCall(tlsGet,0,errorResult))
        return 1;

    memcpy(&nativeError,teb+0x68,4);

    if(nativeError!=0)
        return 1;

    puts("TLS SUCCESS LASTERROR CLEARING PASSED");

    if(!errorCall(errorSet,0x1234,errorResult))
        return 1;



    puts("EXPANDED NATIVE TEB INITIALIZED");


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

    
    const auto heapApi=runtime.bind(
        "api-ms-win-crt-heap-l1-1-0.dll","malloc");

    const auto virtualApi=runtime.bind(
        "api-ms-win-core-memory-l1-1-0.dll",
        "VirtualAlloc");

    uint64_t guestHeap=0;
    uint64_t guestVirtual=0;

    if(!heapApi || !virtualApi)
        return 1;

    if(!runtime.imports.dispatch(
        heapApi,runtime.memory,4096,guestHeap)
        || !guestHeap)
        return 1;

    if(!runtime.imports.dispatch(
        virtualApi,runtime.memory,
        0,guestVirtual,4096,0x3000,4)
        || !guestVirtual)
        return 1;

    constexpr uint64_t guestMagic=
        0xA11E0503C1234567ULL;

    std::array<uint8_t,8> seed{};
    memcpy(seed.data(),&guestMagic,8);

    if(runtime.memory.write(guestHeap,seed)
        !=genesis::GuestMemory64::Fault::none)
        return 1;

    printf("Guest heap: 0x%llx\n",
        (unsigned long long)guestHeap);

    printf("Guest virtual memory: 0x%llx\n",
        (unsigned long long)guestVirtual);

    
    constexpr uint64_t sparseBase=
        genesis::GuestMemory64::DirectSparseBase;

    constexpr uint64_t sparseSize=16ULL<<30;

    constexpr uint64_t sparseEnd=
        sparseBase+sparseSize-4096;

    if(runtime.memory.mapSparse(
        sparseBase,sparseSize,3)
        !=genesis::GuestMemory64::Fault::none)
        return 1;

    std::array<uint8_t,8> sparseSeed{};
    memcpy(sparseSeed.data(),&guestMagic,8);

    if(runtime.memory.write(
        sparseBase,sparseSeed)
        !=genesis::GuestMemory64::Fault::none)
        return 1;

    puts("16 GIB NATIVE SPARSE MAPPING PASSED");

    FEXCore::Core::CPUState initial{};
    initial.gregs[14]=sparseBase;
    initial.gregs[15]=sparseEnd;

    initial.gregs[12]=guestHeap;
    initial.gregs[13]=guestVirtual;


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

    printf("CALLRET stack initialized: %zu bytes\n",
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

    bridge.stackBase =
        reinterpret_cast<uint64_t>(stack);
    bridge.stackSize = page;
    bridge.codeBase = CodeBase;
    bridge.codeSize = sizeof(guest);


    uint64_t expected[3]{};

    // Obtain reference results from Scarlett itself.
    for (unsigned i = 0; i < 3; ++i) {
        if (!runtime.imports.dispatch(
                bindings[i], runtime.memory,
                0, expected[i])) {
            puts("Reference dispatch failed");
            return 1;
        }

        bridge.bind(
            thunkBase + 0x200 + i * 16,
            names[i],
            [&, i](Frame& frame) -> uint64_t {
                return runtime.invoke(
                    bindings[i], frame);
            });
    }

    const uint64_t expectedRax =
        expected[0] + expected[1] + expected[2];

    bool passed = false;

    for (unsigned i = 0; i < 4; ++i) {
        if (!SavedFrame || UnexpectedSyscall)
            break;

        if (SavedFrame->State.rip ==
                CodeBase + sizeof(guest)) {

            const auto& result = SavedFrame->State;

            printf("RAX: %llu\n",
                (unsigned long long)result.gregs[0]);

            printf("HLE calls: %llu\n",
                (unsigned long long)bridge.calls);

            passed =
                result.gregs[0] == expectedRax &&
                result.gregs[4] == initial.gregs[4] &&
                bridge.calls == 3 && runtime.calls == 3 &&
                SavedFrame->SynchronousFaultData.Signal ==
                    FEXCore::Core::FAULT_SIGTRAP;

            break;
        }

        if (!bridge.dispatch(*SavedFrame)) {
            
            printf("Trap RIP: 0x%llx\n",
                (unsigned long long)SavedFrame->State.rip);
            printf("Trap signal: %u\n",
                unsigned(SavedFrame->SynchronousFaultData.Signal));
            printf("PE entry: 0x%llx\n",
                (unsigned long long)CodeBase);
            printf("Thunk base: 0x%llx\n",
                (unsigned long long)HLECodeBase);
            puts("UNHANDLED GUEST TRAP");

            break;
        }

        SavedFrame->State.callret_sp = callretTop;
        SavedFrame = nullptr;

        if (setjmp(ExitPoint) == 0) {
            ctx->ExecuteThread(thread);
        }
    }

    
    if(passed){
        std::array<uint8_t,8> heapResult{};
        std::array<uint8_t,8> virtualResult{};

        using MemoryFault=genesis::GuestMemory64::Fault;

        const bool heapRead=
            runtime.memory.read(
                guestHeap+8,heapResult)==MemoryFault::none;

        const bool virtualRead=
            runtime.memory.read(
                guestVirtual,virtualResult)==MemoryFault::none;

        uint64_t heapValue=0;
        uint64_t virtualValue=0;

        memcpy(&heapValue,heapResult.data(),8);
        memcpy(&virtualValue,virtualResult.data(),8);

        const bool heapOK=
            heapRead && heapValue==guestMagic;

        const bool virtualOK=
            virtualRead && virtualValue==guestMagic;

        puts(heapOK?
            "FEX TRANSLATED HEAP ACCESS PASSED":
            "FEX TRANSLATED HEAP ACCESS FAILED");

        puts(virtualOK?
            "FEX TRANSLATED VIRTUAL ACCESS PASSED":
            "FEX TRANSLATED VIRTUAL ACCESS FAILED");

        passed=passed && heapOK && virtualOK;
    }

    
    if(passed){
        std::array<uint8_t,8> sparseResult{};

        const bool readOK=
            runtime.memory.read(
                sparseEnd,sparseResult)
            ==genesis::GuestMemory64::Fault::none;

        uint64_t sparseValue=0;

        memcpy(&sparseValue,
            sparseResult.data(),8);

        const bool sparseOK=
            readOK && sparseValue==guestMagic;

        puts(sparseOK?
            "FEX TRANSLATED SPARSE ACCESS PASSED":
            "FEX TRANSLATED SPARSE ACCESS FAILED");

        passed=passed && sparseOK;
    }

    
    if(passed && SavedFrame){
        std::array<uint8_t,4> crtResult{};

        const bool readable=
            runtime.memory.read(
                runtime.imports.CrtBase,crtResult)
            ==genesis::GuestMemory64::Fault::none;

        uint32_t commode=0;
        memcpy(&commode,crtResult.data(),4);

        const auto& regs=SavedFrame->State.gregs;

        const bool argcOK=regs[1]==1;
        const bool argvOK=regs[8]=='g';
        const bool writeOK=
            readable && commode==0x12345678;

        puts(argcOK?
            "FEX CRT ARGC ACCESS PASSED":
            "FEX CRT ARGC ACCESS FAILED");

        puts(argvOK?
            "FEX CRT ARGV DEREFERENCE PASSED":
            "FEX CRT ARGV DEREFERENCE FAILED");

        puts(writeOK?
            "FEX CRT GLOBAL WRITE PASSED":
            "FEX CRT GLOBAL WRITE FAILED");

        passed=passed && argcOK && argvOK && writeOK;
    }

    
    if(passed && SavedFrame){
        const auto& regs=SavedFrame->State.gregs;

        const bool selfOK=
            regs[3]==tebAddress;

        const bool processOK=
            regs[6]==1000;

        const bool threadOK=
            regs[7]==1;

        const bool stackOK=
            regs[10]==reinterpret_cast<uint64_t>(
                stack+page) &&
            regs[11]==reinterpret_cast<uint64_t>(
                stack);

        std::array<uint8_t,8> tlsResult{};

        const bool tlsRead=
            runtime.memory.read(
                tebAddress+0x1480,tlsResult)
            ==genesis::GuestMemory64::Fault::none;

        uint64_t tlsValue=0;
        memcpy(&tlsValue,tlsResult.data(),8);

        const bool tlsOK=
            tlsRead && tlsValue==0x12345678;

        puts(selfOK?
            "FEX GS TEB SELF POINTER PASSED":
            "FEX GS TEB SELF POINTER FAILED");

        puts(processOK && threadOK?
            "FEX GS CLIENT ID PASSED":
            "FEX GS CLIENT ID FAILED");

        puts(stackOK?
            "FEX GS STACK LIMITS PASSED":
            "FEX GS STACK LIMITS FAILED");

        puts(tlsOK?
            "FEX GS EXPANDED TLS SLOT PASSED":
            "FEX GS EXPANDED TLS SLOT FAILED");

        passed=passed && selfOK &&
            processOK && threadOK &&
            stackOK && tlsOK;
    }

    
    
    if(passed && SavedFrame){

        const bool gsErrorRead=
            SavedFrame->State.gregs[9]==0x1234;

        uint64_t guestError=0;

        const bool gsErrorWrite=
            errorCall(errorGet,0,guestError) &&
            guestError==0x5678;

        puts(gsErrorRead?
            "FEX GS LASTERROR READ PASSED":
            "FEX GS LASTERROR READ FAILED");

        puts(gsErrorWrite?
            "FEX TO SCARLETT LASTERROR PASSED":
            "FEX TO SCARLETT LASTERROR FAILED");

        passed=passed &&
            gsErrorRead && gsErrorWrite;
    }

    uint64_t tlsFinal=0;

    const bool tlsGuestOK=
        tlsCall(tlsGet,0,0,tlsFinal) &&
        tlsFinal==0x12345678;

    puts(tlsGuestOK?
        "FEX TO SCARLETT TLS COHERENCE PASSED":
        "FEX TO SCARLETT TLS COHERENCE FAILED");

    passed=passed && tlsGuestOK;

    const bool tlsFreeOK=
        tlsCall(tlsFree,0,0,tlsFinal) &&
        tlsFinal==1;

    const bool tlsCleanup=
        runtime.memory.releaseReservation(tlsNative)
        ==genesis::GuestMemory64::Fault::none;

    tebPut64(0x1780,0);

    passed=passed && tlsFreeOK && tlsCleanup;

    puts(tlsCleanup?
        "NATIVE TLS EXPANSION CLEANUP PASSED":
        "NATIVE TLS EXPANSION CLEANUP FAILED");

    ctx->DestroyThread(thread);


    const bool crtClean=
        runtime.memory.unmap(
            runtime.imports.CrtBase,4096)
        ==genesis::GuestMemory64::Fault::none;

    puts(crtClean?
        "NATIVE CRT CLEANUP PASSED":
        "NATIVE CRT CLEANUP FAILED");

    passed=passed && crtClean;


    const bool sparseClean=
        runtime.memory.unmap(
            sparseBase,sparseSize)
        ==genesis::GuestMemory64::Fault::none
        && runtime.memory.nativeSparseCount()==0;

    puts(sparseClean?
        "NATIVE SPARSE CLEANUP PASSED":
        "NATIVE SPARSE CLEANUP FAILED");

    passed=passed && sparseClean;


    {
        uint64_t result=0;

        auto freeApi=runtime.bind(
            "api-ms-win-crt-heap-l1-1-0.dll","free");

        auto releaseApi=runtime.bind(
            "api-ms-win-core-memory-l1-1-0.dll",
            "VirtualFree");

        const bool heapReleased=
            freeApi && runtime.imports.dispatch(
                freeApi,runtime.memory,guestHeap,result);

        const bool virtualReleased=
            releaseApi && runtime.imports.dispatch(
                releaseApi,runtime.memory,
                guestVirtual,result,0,0x8000)
            && result==1;

        const bool clean=
            heapReleased && virtualReleased &&
            runtime.memory.directHeapCount()==0 &&
            runtime.memory.nativeReservationCount()==0;

        puts(clean?
            "TRANSLATED MEMORY CLEANUP PASSED":
            "TRANSLATED MEMORY CLEANUP FAILED");

        passed=passed && clean;
    }

    munmap(callretMapping, callretMappingSize);

    ctx.reset();

    FEXCore::Config::Shutdown();

    munmap(memory, page * 4);

    puts(passed
        ? "FEXCORE SCARLETT PE EXECUTION PASSED"
        : "FEXCORE GUEST EXECUTION FAILED");

    return passed ? 0 : 1;
}
