#pragma once
#include "scarlett_calendar.hpp"
#include "scarlett_unwind64.hpp"
#include "scarlett_runtime64.hpp"
#include "scarlett_crt_format.hpp"
#include <ctime>
#include <arpa/inet.h>
#include "scarlett_files.hpp"
#include <cstdio>
#include <cmath>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#include <limits>
#include <cstdlib>
#include "guest_memory64.hpp"
#include <array>
#include <functional>
#include <vector>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace genesis {

class ScarlettImports64 {
    mutable GuestFiles guestFiles;
public:
    static constexpr uint64_t StubBase = 0x600000000000ull;
    static constexpr uint64_t StubSize = 8192;

    static constexpr uint64_t LegacyCrtBase =
        0x740000000000ULL;

    static constexpr uint64_t NativeCrtBase =
        0x4000000000ULL;

    uint64_t CrtBase=LegacyCrtBase;

    void enableNativeCrt() {
        CrtBase=NativeCrtBase;
    }

    bool install(GuestMemory64& memory) {
        if(memory.map(CrtBase,4096,GuestMemory64::Read|GuestMemory64::Write)!=GuestMemory64::Fault::none)return false;
        const std::array<uint8_t,4> argc{1,0,0,0};
        const std::array<uint8_t,10> arg{'g','u','e','s','t','.','e','x','e',0};
        auto put=[&](uint64_t a,uint64_t v){std::array<uint8_t,8>b{};for(unsigned j=0;j<8;++j)b[j]=uint8_t(v>>(8*j));return memory.write(a,b)==GuestMemory64::Fault::none;};
        if(memory.write(CrtBase+8,argc)!=GuestMemory64::Fault::none || memory.write(CrtBase+128,arg)!=GuestMemory64::Fault::none || !put(CrtBase+16,CrtBase+32) || !put(CrtBase+32,CrtBase+128))return false;
        if(memory.map(StubBase, StubSize, GuestMemory64::Read | GuestMemory64::Execute)!=GuestMemory64::Fault::none)return false;
        // Built-in HLE modules exist independently of static imports.
        for(const char* sym:{"InitializeCriticalSectionEx","InitializeConditionVariable","WakeConditionVariable","WakeAllConditionVariable","InitializeSRWLock","AcquireSRWLockExclusive","ReleaseSRWLockExclusive","TryAcquireSRWLockExclusive","AcquireSRWLockShared","ReleaseSRWLockShared","TryAcquireSRWLockShared"})
            registerImport("api-ms-win-core-synch-l1-2-0.dll",sym);
        for(const char* sym:{"InitializeCriticalSectionAndSpinCount","InitializeCriticalSection","EnterCriticalSection","LeaveCriticalSection","DeleteCriticalSection","TryEnterCriticalSection"})
            registerImport("api-ms-win-core-synch-l1-1-0.dll",sym);
        for(auto sym:{"CreateEventA","CreateEventW","SetEvent","ResetEvent","WaitForSingleObject","WaitForSingleObjectEx"})registerImport("api-ms-win-core-synch-l1-1-0.dll",sym);
        registerImport("api-ms-win-core-handle-l1-1-0.dll","CloseHandle");
        registerImport("api-ms-win-core-synch-l1-2-0.dll","SleepConditionVariableCS");
        registerImport("api-ms-win-core-synch-l1-2-1.dll","WaitForMultipleObjects");
        return true;
    }

    uint64_t registerImport(
        const std::string& inputDll,
        const std::string& symbol) {
        auto dll=normalize(inputDll);
        if(dll=="vcruntime140.dll") dll="VCRUNTIME140.dll";
        if(dll=="msvcp140.dll") dll="MSVCP140.dll";
        if(dll=="advapi32.dll" && symbol=="RegQueryValueExW") dll="ADVAPI32.dll";
        if(symbol.empty()) return 0;

        uint64_t address = 0;
        if(dll=="api-ms-win-core-interlocked-l1-1-0.dll") {
            if(symbol=="InterlockedPushEntrySList") address=StubBase+0x1e00;
            if(symbol=="InterlockedFlushSList") address=StubBase+0x1e10;
            if(symbol=="InterlockedPopEntrySList") address=StubBase+0x1e20;
            if(symbol=="QueryDepthSList") address=StubBase+0x1e30;
        }
        if(dll=="api-ms-win-core-processthreads-l1-1-0.dll" && symbol=="TerminateProcess") address=StubBase+0x1e40;

        if(dll=="api-ms-win-crt-convert-l1-1-0.dll" && symbol=="atol") address=StubBase+0x1d80;
        if(dll=="api-ms-win-core-util-l1-1-0.dll" && symbol=="EncodePointer") address=StubBase+0x1d90;
        if(dll=="api-ms-win-core-util-l1-1-0.dll" && symbol=="DecodePointer") address=StubBase+0x1da0;
        if(dll=="api-ms-win-core-fibers-l1-1-0.dll" && symbol=="FlsAlloc") address=StubBase+0x1db0;
        if(dll=="api-ms-win-core-fibers-l1-1-0.dll" && symbol=="FlsFree") address=StubBase+0x1dc0;
        if(dll=="api-ms-win-core-fibers-l1-1-0.dll" && symbol=="FlsGetValue") address=StubBase+0x1dd0;
        if(dll=="api-ms-win-core-fibers-l1-1-0.dll" && symbol=="FlsSetValue") address=StubBase+0x1de0;
        if(dll=="api-ms-win-core-rtlsupport-l1-1-0.dll" && symbol=="RtlVirtualUnwind") address=StubBase+0x1e50;
        if(dll=="api-ms-win-core-rtlsupport-l1-1-0.dll" && symbol=="RtlPcToFileHeader") address=StubBase+0x1df0;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && (symbol=="terminate" || symbol=="abort")) address=StubBase+(symbol=="terminate"?0x1b00:0x1b10);

        if (dll == "api-ms-win-core-sysinfo-l1-1-0.dll" &&
            symbol == "GetSystemTimeAsFileTime") {
            address = StubBase + 0x100;
        } else if (
            dll == "api-ms-win-core-processthreads-l1-1-0.dll" &&
            symbol == "GetCurrentThreadId") {
            address = StubBase + 0x110;
        } else if (
            dll == "api-ms-win-core-processthreads-l1-1-0.dll" &&
            symbol == "GetCurrentProcessId") {
            address = StubBase + 0x120;
        }

        if (
            dll == "api-ms-win-core-profile-l1-1-0.dll" &&
            symbol == "QueryPerformanceCounter") {
            address = StubBase + 0x130;
        }

        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll") {
            if(symbol=="_initterm_e") address=StubBase+0x140;
            if(symbol=="_initterm") address=StubBase+0x150;
        }
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_set_app_type") address=StubBase+0x300;
        if(dll=="api-ms-win-core-profile-l1-1-0.dll" && symbol=="QueryPerformanceFrequency") address=StubBase+0x310;
        if(dll=="api-ms-win-core-processthreads-l1-1-0.dll" && symbol=="GetCurrentProcess") address=StubBase+0x320;
        if(dll=="api-ms-win-core-errorhandling-l1-1-0.dll" && symbol=="GetLastError") address=StubBase+0x330;
        if(dll=="api-ms-win-core-sysinfo-l1-1-0.dll" && symbol=="GetTickCount64") address=StubBase+0x340;
        if(dll=="api-ms-win-core-interlocked-l1-1-0.dll" && symbol=="InitializeSListHead") address=StubBase+0x350;
        if(dll=="VCRUNTIME140.dll" && symbol=="memcpy") address=StubBase+0x360;
        if(dll=="VCRUNTIME140.dll" && symbol=="memmove") address=StubBase+0x370;
        if(dll=="VCRUNTIME140.dll" && symbol=="memset") address=StubBase+0x380;
        if(dll=="VCRUNTIME140.dll" && symbol=="memcmp") address=StubBase+0x390;
        if(dll=="VCRUNTIME140.dll" && symbol=="memchr") address=StubBase+0x3a0;
        if(dll=="api-ms-win-crt-heap-l1-1-0.dll" && symbol=="malloc") address=StubBase+0x3b0;
        if(dll=="api-ms-win-crt-heap-l1-1-0.dll" && symbol=="calloc") address=StubBase+0x3c0;
        if(dll=="api-ms-win-crt-heap-l1-1-0.dll" && symbol=="free") address=StubBase+0x3d0;
        if(dll=="api-ms-win-crt-heap-l1-1-0.dll" && symbol=="realloc") address=StubBase+0x3e0;
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" && symbol=="_set_fmode") address=StubBase+0x400;
        if(dll=="api-ms-win-crt-heap-l1-1-0.dll" && symbol=="_set_new_mode") address=StubBase+0x410;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_set_errno") address=StubBase+0x420;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_get_errno") address=StubBase+0x430;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strlen") address=StubBase+0x440;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="wcslen") address=StubBase+0x450;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strcmp") address=StubBase+0x460;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strncmp") address=StubBase+0x470;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="wcscmp") address=StubBase+0x480;
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" && symbol=="__p__commode") address=StubBase+0x490;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="__p___argc") address=StubBase+0x4a0;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="__p___argv") address=StubBase+0x4b0;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_errno") address=StubBase+0x4c0;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_get_narrow_winmain_command_line") address=StubBase+0x4d0;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_initialize_narrow_environment") address=StubBase+0x4e0;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_configure_narrow_argv") address=StubBase+0x4f0;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_initialize_onexit_table") address=StubBase+0x500;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_crt_atexit") address=StubBase+0x510;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_cexit") address=StubBase+0x520;
        if(dll=="api-ms-win-crt-locale-l1-1-0.dll" && symbol=="_configthreadlocale") address=StubBase+0x530;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="InitializeCriticalSectionAndSpinCount") address=StubBase+0x540;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="InitializeCriticalSection") address=StubBase+0x550;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="EnterCriticalSection") address=StubBase+0x560;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="LeaveCriticalSection") address=StubBase+0x570;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="DeleteCriticalSection") address=StubBase+0x580;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="TryEnterCriticalSection") address=StubBase+0x590;
        if(dll=="api-ms-win-core-libraryloader-l1-2-0.dll") {
            if(symbol=="GetModuleHandleW") address=StubBase+0x5a0;
            if(symbol=="GetModuleHandleA") address=StubBase+0x5b0;
            if(symbol=="GetProcAddress") address=StubBase+0x5c0;
        }
        if(dll=="api-ms-win-core-processthreads-l1-1-1.dll" && symbol=="IsProcessorFeaturePresent") address=StubBase+0x5d0;
        if(dll=="api-ms-win-core-rtlsupport-l1-1-0.dll" && symbol=="RtlCaptureContext") address=StubBase+0x5e0;
        if(dll=="api-ms-win-core-rtlsupport-l1-1-0.dll" && symbol=="RtlLookupFunctionEntry") address=StubBase+0x5f0;
        if(dll=="api-ms-win-core-errorhandling-l1-1-0.dll" && symbol=="SetLastError") address=StubBase+0x600;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="tolower") address=StubBase+0x610;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="toupper") address=StubBase+0x620;
        if(dll=="VCRUNTIME140.dll" && symbol=="strchr") address=StubBase+0x630;
        if(dll=="VCRUNTIME140.dll" && symbol=="strrchr") address=StubBase+0x640;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strcpy") address=StubBase+0x650;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strncpy") address=StubBase+0x660;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strcat") address=StubBase+0x670;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="wcsncmp") address=StubBase+0x680;
        if(dll=="api-ms-win-core-sysinfo-l1-2-0.dll" && symbol=="GetSystemTimePreciseAsFileTime") address=StubBase+0x690;
        if(dll=="api-ms-win-core-synch-l1-2-0.dll") {
            const std::array<const char*,11> names{"InitializeCriticalSectionEx","InitializeConditionVariable","WakeConditionVariable","WakeAllConditionVariable","InitializeSRWLock","AcquireSRWLockExclusive","ReleaseSRWLockExclusive","TryAcquireSRWLockExclusive","AcquireSRWLockShared","ReleaseSRWLockShared","TryAcquireSRWLockShared"};
            for(unsigned i=0;i<names.size();++i)if(symbol==names[i])address=StubBase+0x6a0+i*16;
        }
        if(dll=="api-ms-win-core-synch-l1-1-0.dll") {
            const std::array<const char*,6> names{"CreateEventA","CreateEventW","SetEvent","ResetEvent","WaitForSingleObject","WaitForSingleObjectEx"};
            for(unsigned i=0;i<names.size();++i)if(symbol==names[i])address=StubBase+0x760+i*16;
        }
        if(dll=="api-ms-win-core-handle-l1-1-0.dll" && symbol=="CloseHandle")address=StubBase+0x7c0;
        if(dll=="api-ms-win-core-synch-l1-2-0.dll" && symbol=="SleepConditionVariableCS")address=StubBase+0x7d0;
        if(dll=="api-ms-win-core-synch-l1-2-1.dll" && symbol=="WaitForMultipleObjects")address=StubBase+0x7e0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll") {
            const std::array<const char*,13> names{"isalnum","isalpha","isdigit","islower","isspace","isxdigit","_stricmp","_strnicmp","_wcsnicmp","strcspn","strpbrk","wcsncpy","strncat"};
            for(unsigned i=0;i<names.size();++i)if(symbol==names[i])address=StubBase+0x800+i*16;
        }
        if(dll=="api-ms-win-crt-utility-l1-1-0.dll") {
            if(symbol=="rand")address=StubBase+0x8d0;
            if(symbol=="srand")address=StubBase+0x8e0;
        }
        if(normalize(dll)=="advapi32.dll") {
            if(symbol=="RegOpenKeyW")address=StubBase+0x8f0;
            if(symbol=="RegCloseKey")address=StubBase+0x900;
        }
        if(dll=="api-ms-win-crt-math-l1-1-0.dll") {
            const std::array<const char*,33> names{"acos","acosf","asin","asinf","atan","atan2","atan2f","atanf","cbrtf","ceilf","cos","cosf","erff","exp","exp2","exp2f","expf","fmod","fmodf","log","log10f","log2","log2f","logf","pow","powf","remainderf","sin","sinf","sinhf","tan","tanf","nextafterf"};
            for(unsigned i=0;i<names.size();++i)if(symbol==names[i])address=StubBase+0x910+i*16;
        }
        if(dll=="api-ms-win-crt-convert-l1-1-0.dll") {
            const std::array<const char*,8> names{"_strtoi64","_strtoui64","atoi","atoll","strtol","strtoll","strtoul","strtoull"};
            for(unsigned i=0;i<names.size();++i)if(symbol==names[i])address=StubBase+0xb20+i*16;
        }
        if(dll=="VCRUNTIME140.dll" && symbol=="strstr") address=StubBase+0xba0;
        if(dll=="VCRUNTIME140.dll" && symbol=="wcsrchr") address=StubBase+0xbb0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strcpy_s") address=StubBase+0xbc0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strcat_s") address=StubBase+0xbd0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strncpy_s") address=StubBase+0xbe0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="wcscat_s") address=StubBase+0xbf0;
        if(dll=="api-ms-win-core-memory-l1-1-0.dll" && symbol=="VirtualAlloc") address=StubBase+0xc20;
        if(dll=="api-ms-win-core-memory-l1-1-0.dll" && symbol=="VirtualFree") address=StubBase+0xc30;
        if(dll=="api-ms-win-core-processthreads-l1-1-0.dll" && symbol=="GetProcessId") address=StubBase+0xc40;
        if(dll=="api-ms-win-core-processenvironment-l1-1-0.dll" && symbol=="GetCommandLineA") address=StubBase+0xc50;
        if(dll=="api-ms-win-core-debug-l1-1-0.dll" && symbol=="IsDebuggerPresent") address=StubBase+0xc60;
        if(dll=="MSVCP140.dll" && symbol=="_Query_perf_counter") address=StubBase+0xc90;
        if(dll=="MSVCP140.dll" && symbol=="_Query_perf_frequency") address=StubBase+0xca0;
        if(dll=="MSVCP140.dll" && symbol=="_Xtime_get_ticks") address=StubBase+0xcb0;
        if(dll=="api-ms-win-crt-time-l1-1-0.dll" && symbol=="_time64") address=StubBase+0xcc0;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="AcquireSRWLockExclusive") address=StubBase+0xcd0;
        if(dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="ReleaseSRWLockExclusive") address=StubBase+0xce0;
        if(dll=="api-ms-win-core-com-l1-1-0.dll" && symbol=="StringFromGUID2") address=StubBase+0xcf0;
        if(dll=="api-ms-win-core-file-l1-1-0.dll" && symbol=="FileTimeToLocalFileTime") address=StubBase+0xd00;
        if(dll=="api-ms-win-core-file-l1-1-0.dll" && symbol=="LocalFileTimeToFileTime") address=StubBase+0xd10;
        if((dll=="kernel32.dll" ||
            dll=="kernelbase.dll" ||
            dll.starts_with("api-ms-win-core-synch-"))
            && symbol=="CreateSemaphoreExW") address=StubBase+0xd20;
        if((dll=="kernel32.dll" ||
            dll=="kernelbase.dll" ||
            dll.starts_with("api-ms-win-core-synch-"))
            && symbol=="ReleaseSemaphore") address=StubBase+0xd30;
        if((dll=="kernel32.dll" ||
            dll=="kernelbase.dll" ||
            dll.starts_with("api-ms-win-core-synch-"))
            && symbol=="CreateSemaphoreW") address=StubBase+0xd40;
        if(dll=="api-ms-win-core-sysinfo-l1-1-0.dll" && symbol=="GetLogicalProcessorInformation") address=StubBase+0xd50;
        if(dll=="api-ms-win-core-errorhandling-l1-1-0.dll" && symbol=="SetUnhandledExceptionFilter") address=StubBase+0xd60;
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" && symbol=="_set_invalid_parameter_handler") address=StubBase+0xd70;
        if(dll=="VCRUNTIME140.dll" && symbol=="_set_purecall_handler") address=StubBase+0xd80;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="__setusermatherr") address=StubBase+0xd90;
        if(dll=="api-ms-win-core-debug-l1-1-0.dll" && symbol=="OutputDebugStringA") address=StubBase+0xda0;
        if(dll=="api-ms-win-crt-convert-l1-1-0.dll" && symbol=="_itoa") address=StubBase+0xdb0;
        if(dll=="api-ms-win-core-string-obsolete-l1-1-0.dll" && symbol=="lstrcmpW") address=StubBase+0xdc0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="wcscoll") address=StubBase+0xdd0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="_wcsicoll") address=StubBase+0xde0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strtok") address=StubBase+0xdf0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strtok_s") address=StubBase+0xe00;
        if(dll=="ADVAPI32.dll" && symbol=="RegQueryValueExW") address=StubBase+0xe10;
        if(dll=="api-ms-win-crt-convert-l1-1-0.dll") {
            if(symbol=="atof") address=StubBase+0xe20;
            if(symbol=="strtod") address=StubBase+0xe30;
            if(symbol=="strtof") address=StubBase+0xe40;
        }
        if(dll=="api-ms-win-crt-math-l1-1-0.dll") {
            if(symbol=="modf") address=StubBase+0xe50;
            if(symbol=="modff") address=StubBase+0xe60;
            if(symbol=="_fdsign") address=StubBase+0xe70;
            if(symbol=="lroundf") address=StubBase+0xe80;
            if(symbol=="_fdtest") address=StubBase+0xe90;
            if(symbol=="_dtest") address=StubBase+0xea0;
        }
        if (normalize(dll)=="ws2_32.dll") {
            if (symbol=="htons" || symbol=="#9") address=StubBase+0xeb0;
            if (symbol=="ntohs" || symbol=="#15") address=StubBase+0xec0;
            if (symbol=="htonl" || symbol=="#8") address=StubBase+0xed0;
            if (symbol=="ntohl" || symbol=="#14") address=StubBase+0xee0;
        }
        if (dll=="api-ms-win-core-timezone-l1-1-0.dll") {
            if (symbol=="SystemTimeToFileTime") address=StubBase+0xef0;
            if (symbol=="FileTimeToSystemTime") address=StubBase+0xf00;
        }
        if (dll=="api-ms-win-crt-stdio-l1-1-0.dll") {
            for (size_t i=0;i<GuestFiles::names.size();++i)
                if (symbol==GuestFiles::names[i]) address=StubBase+0xf10+i*16;
        }
        if (dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="nexttowardf") address=StubBase+0xfc0;
        if (dll=="api-ms-win-crt-time-l1-1-0.dll" && symbol=="_difftime64") address=StubBase+0xfd0;
        if (dll=="api-ms-win-core-processthreads-l1-1-1.dll" && symbol=="GetCurrentThreadStackLimits") address=StubBase+0xfe0;
        if (dll=="api-ms-win-crt-time-l1-1-0.dll") {
            if(symbol=="_gmtime64_s") address=StubBase+0xff0;
            if(symbol=="_localtime64_s") address=StubBase+0x1000;
            if(symbol=="_ftime64") address=StubBase+0x1010;
        }
        if((dll=="api-ms-win-core-memory-l1-1-0.dll" || normalize(dll)=="kernel32.dll") && symbol=="VirtualProtect") address=StubBase+0x1020;

        // V80 runtime services
        {
            const auto key=normalize(dll);

            if(key=="kernel32.dll" ||
               key.starts_with("api-ms-win-core-processthreads-")){
                if(symbol=="TlsAlloc")address=StubBase+0x1030;
                if(symbol=="TlsFree")address=StubBase+0x1040;
                if(symbol=="TlsGetValue")address=StubBase+0x1050;
                if(symbol=="TlsSetValue")address=StubBase+0x1060;
                if(symbol=="GetCurrentThread")address=StubBase+0x1070;
                if(symbol=="GetThreadId")address=StubBase+0x1080;
            }

            if(key=="kernel32.dll" ||
               key.starts_with("api-ms-win-core-interlocked-")){
                if(symbol=="InterlockedIncrement")address=StubBase+0x1090;
                if(symbol=="InterlockedDecrement")address=StubBase+0x10a0;
                if(symbol=="InterlockedExchange")address=StubBase+0x10b0;
                if(symbol=="InterlockedExchangeAdd")address=StubBase+0x10c0;
                if(symbol=="InterlockedCompareExchange")address=StubBase+0x10d0;
                if(symbol=="InterlockedCompareExchange64")address=StubBase+0x10e0;
            }
        }
        if(normalize(dll)=="kernel32.dll"){
            if(symbol=="SetLastError")address=StubBase+0x600;
            if(symbol=="GetLastError")address=StubBase+0x330;
        }

        if(normalize(dll)=="kernel32.dll" ||
           normalize(dll).starts_with("api-ms-win-core-processthreads-")){
            if(symbol=="CreateThread")address=StubBase+0x10f0;
            if(symbol=="ExitThread")address=StubBase+0x1100;
            if(symbol=="GetExitCodeThread")address=StubBase+0x1110;
        }

        if(dll=="api-ms-win-core-file-l1-1-0.dll" || dll=="api-ms-win-core-file-l2-1-0.dll" ||
           normalize(dll)=="kernel32.dll") {
            for(size_t i=0;i<GuestFiles::winNames.size();++i)
                if(symbol==GuestFiles::winNames[i])address=StubBase+0x1120+i*16;
        }
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll"){
            if(symbol=="_wfopen")address=StubBase+0x11e0;
            if(symbol=="fgetpos")address=StubBase+0x11f0;
            if(symbol=="fsetpos")address=StubBase+0x1200;
        }
        if(dll=="api-ms-win-crt-filesystem-l1-1-0.dll" && symbol=="remove")address=StubBase+0x1210;
        if(normalize(dll)=="ws2_32.dll"){
            if(symbol=="inet_addr" || symbol=="#11")address=StubBase+0x1220;
            if(symbol=="WSAGetLastError" || symbol=="#111")address=StubBase+0x1230;
            if(symbol=="__WSAFDIsSet" || symbol=="#151")address=StubBase+0x1240;
        }
        if(dll=="api-ms-win-core-sysinfo-l1-1-0.dll"){
            if(symbol=="GetLocalTime")address=StubBase+0x1250;
            if(symbol=="GetSystemTime")address=StubBase+0x1260;
        }
        if(normalize(dll)=="mfplat.dll" && symbol=="MFGetSystemTime")address=StubBase+0x1270;
        
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" &&
           symbol=="__stdio_common_vsprintf")
            address=StubBase+0x1280;

        
        if(normalize(dll)=="msvcp140.dll" &&
           symbol=="?_Random_device@std@@YAIXZ")
            address=StubBase+0x1290;


        // V83: CRT TLS destructor registration.
        if(dll=="api-ms-win-crt-runtime-l1-1-0.dll" &&
           symbol=="_register_thread_local_exe_atexit_callback")
            address=StubBase+0x12a0;

        // Experimental observed-callsite profile, disabled by default.
        if(std::getenv("ALIEN_XBOX_MEMORY_EXPERIMENT")) {
            if(dll=="d3d12_xs.dll" && symbol=="D3D12ConfigureVirtualMemoryX") address=StubBase+0xc70;
            if(dll=="xmem.dll" && symbol=="XMemVirtualAlloc") address=StubBase+0xc80;
        }
        // Resolve the standard D3D12 export only when
        // the graphics implementation is installed.
        if(normalize(dll)=="d3d12.dll" &&
           symbol=="D3D12CreateDevice" &&
           isGraphicsStub(StubBase+0x1400)){
            address=StubBase+0x1400;
        }
        if(normalize(dll)=="d3d12_xs.dll" &&
           symbol=="D3D12XboxCreateDevice" &&
           isGraphicsStub(StubBase+0x1440)){
            address=StubBase+0x1440;
        }


        // ALIEN diagnostic GPU ABI, not an Xbox API.
        if(normalize(dll)=="alien_gpu.dll"){
            uint64_t offset=0;
            if(symbol=="AlienGpuCreateBuffer") offset=0x1500;
            if(symbol=="AlienGpuDestroyBuffer") offset=0x1510;
            if(symbol=="AlienGpuUpload") offset=0x1520;
            if(symbol=="AlienGpuDownload") offset=0x1530;
            if(symbol=="AlienGpuSubmit") offset=0x1540;
            if(symbol=="AlienGpuFence") offset=0x1550;
            if(symbol=="AlienGpuDrawTriangles")
                offset=0x1560;

            if(offset && isGraphicsStub(StubBase+offset))
                address=StubBase+offset;
        }

        // V82 batch: symbol-keyed HLE services in a dedicated stub window.
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" && symbol=="__stdio_common_vsprintf_s") address=StubBase+0x1d30;
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" && symbol=="__stdio_common_vsnprintf_s") address=StubBase+0x1d40;
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" && symbol=="__stdio_common_vswprintf") address=StubBase+0x1d50;
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" && symbol=="__stdio_common_vswprintf_s") address=StubBase+0x1d60;
        if(dll=="api-ms-win-crt-stdio-l1-1-0.dll" && symbol=="__stdio_common_vsnwprintf_s") address=StubBase+0x1d70;
        if(!address) {
            for(unsigned i=0;i<v82Names.size();++i)
                if(symbol==v82Names[i] && (i<v82XboxFirst || std::getenv("ALIEN_XBOX_MEMORY_EXPERIMENT"))){
                    address=StubBase+0x1800+i*16;break;
                }
        }

        if(!address && dll=="kernel32.dll" && symbol=="AcquireSRWLockExclusive") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="ReleaseSRWLockExclusive") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="CloseHandle") address=registerImport("api-ms-win-core-handle-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="CreateEventW") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="DeleteCriticalSection") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="EnterCriticalSection") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="LeaveCriticalSection") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="InitializeCriticalSection") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="GetCurrentProcess") address=registerImport("api-ms-win-core-processthreads-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="GetCurrentProcessId") address=registerImport("api-ms-win-core-processthreads-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="GetCurrentThreadId") address=registerImport("api-ms-win-core-processthreads-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="GetModuleHandleW") address=registerImport("api-ms-win-core-libraryloader-l1-2-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="GetProcAddress") address=registerImport("api-ms-win-core-libraryloader-l1-2-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="GetSystemTimeAsFileTime") address=registerImport("api-ms-win-core-sysinfo-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="InitializeSListHead") address=registerImport("api-ms-win-core-interlocked-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="IsDebuggerPresent") address=registerImport("api-ms-win-core-debug-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="IsProcessorFeaturePresent") address=registerImport("api-ms-win-core-processthreads-l1-1-1.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="OutputDebugStringA") address=registerImport("api-ms-win-core-debug-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="QueryPerformanceCounter") address=registerImport("api-ms-win-core-profile-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="RtlCaptureContext") address=registerImport("api-ms-win-core-rtlsupport-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="RtlLookupFunctionEntry") address=registerImport("api-ms-win-core-rtlsupport-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="SetEvent") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="SetUnhandledExceptionFilter") address=registerImport("api-ms-win-core-errorhandling-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="WaitForSingleObject") address=registerImport("api-ms-win-core-synch-l1-1-0.dll",symbol);
        if(!address && dll=="kernel32.dll" && symbol=="WakeAllConditionVariable") address=registerImport("api-ms-win-core-synch-l1-2-0.dll",symbol);
        if(!address && dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="AcquireSRWLockShared") address=registerImport("api-ms-win-core-synch-l1-2-0.dll",symbol);
        if(!address && dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="ReleaseSRWLockShared") address=registerImport("api-ms-win-core-synch-l1-2-0.dll",symbol);
        if(!address && dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="InitializeSRWLock") address=registerImport("api-ms-win-core-synch-l1-2-0.dll",symbol);
        if(!address && dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="InitializeCriticalSectionEx") address=registerImport("api-ms-win-core-synch-l1-2-0.dll",symbol);
        if(!address && dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="TryAcquireSRWLockExclusive") address=registerImport("api-ms-win-core-synch-l1-2-0.dll",symbol);
        if(!address && dll=="api-ms-win-core-synch-l1-1-0.dll" && symbol=="TryAcquireSRWLockShared") address=registerImport("api-ms-win-core-synch-l1-2-0.dll",symbol);
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="ceil") address=StubBase+0x1c00;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="cosh") address=StubBase+0x1c10;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="expm1") address=StubBase+0x1c20;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="floor") address=StubBase+0x1c30;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="log1p") address=StubBase+0x1c40;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="sinh") address=StubBase+0x1c50;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="sqrt") address=StubBase+0x1c60;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="sqrtf") address=StubBase+0x1c70;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="_dsign") address=StubBase+0x1c80;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="_ldsign") address=StubBase+0x1c90;
        if(dll=="api-ms-win-crt-math-l1-1-0.dll" && symbol=="_isnan") address=StubBase+0x1ca0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="isupper") address=StubBase+0x1cb0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="iswalnum") address=StubBase+0x1cc0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="iswdigit") address=StubBase+0x1cd0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="iswspace") address=StubBase+0x1ce0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="iswxdigit") address=StubBase+0x1cf0;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="wcsnlen") address=StubBase+0x1d00;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="__strncnt") address=StubBase+0x1d10;
        if(dll=="api-ms-win-crt-string-l1-1-0.dll" && symbol=="strspn") address=StubBase+0x1d20;
        if (address) {
            imports[address] = symbol;
            auto key=normalize(dll);
            if(!modules.contains(key)) modules.emplace(key,0x750000000000ull+modules.size()*4096);
            exports[key][symbol]=address;
            if(key.starts_with("api-ms-win-core-")) {
                const std::string kernel="kernel32.dll";
                if(!modules.contains(kernel))modules.emplace(kernel,0x750000000000ull+modules.size()*4096);
                exports[kernel][symbol]=address;
            }
        }

        return address;
    }

    using DynamicLoader=std::function<uint64_t(const std::string&)>;
    void bindDynamicLoader(DynamicLoader loader){dynamicLoader=std::move(loader);}
    bool publishEntrylessModule(const std::string& key,uint64_t base,const std::map<std::string,uint64_t>& symbols){
        if(!base || (modules.contains(key)&&modules.at(key)!=base))return false;
        modules[key]=base; for(const auto& [name,address]:symbols)exports[key][name]=address;
        exports.try_emplace(key); return true;
    }
    void bindThreadFinishedQuery(
        std::function<bool(uint64_t)> query){
        threadFinishedQuery=std::move(query);
    }

    struct WaitRequest {
        uint64_t handle=0;
        uint32_t timeout=0;
    };

    void enableCooperativeWaits(bool enabled){
        cooperativeWaits=enabled;
    }

    bool takeWaitRequest(WaitRequest& request) const {
        if(!waitPending)return false;
        request=pendingWait;
        waitPending=false;
        return true;
    }

    bool pollThreadWait(uint64_t handle,
                        uint64_t& result) const {
        if(auto e=events.find(handle);e!=events.end()){
            if(!e->second.signaled){
                result=258;
                return true;
            }

            if(!e->second.manual)
                e->second.signaled=false;

            result=0;
            return true;
        }

        if(auto sem=semaphores.find(handle);
           sem!=semaphores.end()){
            if(!sem->second.first){
                result=258;
                return true;
            }

            --sem->second.first;
            result=0;
            return true;
        }

        auto it=threadHandles.find(handle);

        if(it==threadHandles.end()){
            lastError=6;
            result=UINT32_MAX;
            return true;
        }

        uint32_t code=259;

        if(!threadExitQuery ||
           !threadExitQuery(it->second,code))
            return false;

        result=(threadFinishedQuery &&
                threadFinishedQuery(it->second))
                ?0:258;

        return true;
    }

    bool hasWaitRequest() const {
        return waitPending;
    }

    using ThreadExitQuery =
        std::function<bool(uint64_t,uint32_t&)>;

    void bindThreadExitQuery(ThreadExitQuery query){
        threadExitQuery=std::move(query);
    }

    using ThreadCreator =
        std::function<uint64_t(uint64_t,uint64_t,uint64_t)>;

    void bindThreadCreator(ThreadCreator creator){
        threadCreator=std::move(creator);
    }

    void selectThread(uint64_t id,uint64_t teb) const {
        threadLocals[activeThread].error=lastError;
        activeThread=id;
        activeTeb=teb;
        lastError=threadLocals[id].error;
    }

    uint64_t currentThread() const {
        return activeThread;
    }

    void setImageBase(uint64_t base) {imageBase=base;}
    void setExceptionDirectory(uint32_t size,uint32_t rva,uint32_t bytes) {imageSize=size; exceptionRva=rva; exceptionSize=bytes;}
    std::string name(uint64_t address) const {
        auto it=imports.find(address);
        return it==imports.end()?std::string{}:it->second;
    }
    bool hasExitCallback() const {return !exitCallbacks.empty();}
    uint64_t popExitCallback() const {auto fn=exitCallbacks.back();exitCallbacks.pop_back();return fn;}
    bool contains(uint64_t address) const {
        return imports.contains(address);
    }

    using AbiArguments = std::array<uint64_t,16>;

    static bool collectAbiArguments(
        const GuestMemory64& memory,
        uint64_t rsp,
        bool tailJump,
        uint64_t rcx,
        uint64_t rdx,
        uint64_t r8,
        uint64_t r9,
        unsigned count,
        AbiArguments& result) {

        if(count>result.size())return false;

        AbiArguments args{};
        args[0]=rcx;
        args[1]=rdx;
        args[2]=r8;
        args[3]=r9;

        for(unsigned i=4;i<count;++i){
            const uint64_t offset=
                32+(tailJump?8:0)+(i-4)*8;

            if(rsp>UINT64_MAX-offset)
                return false;

            std::array<uint8_t,8> bytes{};

            if(memory.read(rsp+offset,bytes)
                !=GuestMemory64::Fault::none)
                return false;

            for(unsigned j=0;j<8;++j)
                args[i]|=uint64_t(bytes[j])<<(j*8);
        }

        result=args;
        return true;
    }

    using GraphicsDispatch = std::function<bool(
        uint64_t,GuestMemory64&,
        const AbiArguments&,uint64_t&)>;

    void bindGraphicsDispatch(GraphicsDispatch fn){
        graphicsDispatch=std::move(fn);
    }

    bool isGraphicsStub(uint64_t address) const {
        return address>=StubBase+0x1400 &&
               address<StubBase+0x1800 &&
               ((address-StubBase)&15)==0 &&
               contains(address);
    }

    bool registerGraphicsStub(
        uint64_t offset,const std::string& symbol){
        if(offset<0x1400 || offset>=0x1800 ||
           (offset&15) || symbol.empty())
            return false;

        return imports.emplace(
            StubBase+offset,symbol).second;
    }

    bool dispatchGraphics(
        uint64_t address,GuestMemory64& memory,
        uint64_t rsp,bool tailJump,
        uint64_t rcx,uint64_t rdx,
        uint64_t r8,uint64_t r9,
        uint64_t& rax) const {

        if(!isGraphicsStub(address) ||
           !graphicsDispatch)return false;

        AbiArguments args{};

        const auto symbol=name(address);
        unsigned count=1;

        if(symbol=="D3D12CreateDevice"||symbol=="D3D12XboxCreateDevice")count=4;
        else if(symbol=="GraphicsQueryInterface")count=3;
        else if(symbol=="AlienGpuCreateBuffer")count=2;
        else if(symbol=="AlienGpuDestroyBuffer")count=1;
        else if(symbol=="AlienGpuUpload")count=4;
        else if(symbol=="AlienGpuDownload")count=4;
        else if(symbol=="AlienGpuSubmit")count=2;
        else if(symbol=="AlienGpuFence")count=1;
        else if(symbol=="AlienGpuDrawTriangles")count=9;
        else if(symbol!="GraphicsAddRef" &&
                symbol!="GraphicsRelease")
            return false;

        if(!collectAbiArguments(
            memory,rsp,tailJump,
            rcx,rdx,r8,r9,count,args))
            return false;

        return graphicsDispatch(
            address,memory,args,rax);
    }

    bool dispatch(
        uint64_t address,
        GuestMemory64& memory,
        uint64_t rcx,
        uint64_t& rax, uint64_t rdx=0, uint64_t r8=0, uint64_t r9=0, uint64_t arg5=UINT64_MAX, uint64_t arg6=UINT64_MAX, std::array<uint8_t,16>* fp=nullptr,uint64_t arg7=0,uint64_t arg8=UINT64_MAX) const {

        const auto it = imports.find(address);
        if (it == imports.end())
            return false;

        const auto& n=it->second;
        // V83: Microsoft C++ random_device.
        if(n=="?_Random_device@std@@YAIXZ"){
            uint32_t value=0;
            auto* ptr=reinterpret_cast<uint8_t*>(&value);
            int fd=::open("/dev/urandom",
                O_RDONLY|O_CLOEXEC);

            if(fd<0)return false;

            size_t done=0;

            while(done<sizeof(value)){
                auto count=::read(
                    fd,ptr+done,sizeof(value)-done);

                if(count<0 && errno==EINTR)
                    continue;

                if(count<=0){
                    ::close(fd);
                    return false;
                }

                done+=size_t(count);
            }

            ::close(fd);

            rax=uint64_t(value);
            return true;
        }

        if(n=="__stdio_common_vsprintf_s" || n=="__stdio_common_vswprintf_s" || n=="__stdio_common_vswprintf")
            return guestCrtFormat(memory,rcx,rdx,r8,r9,arg5,arg6,rax,n!="__stdio_common_vswprintf",UINT64_MAX,false,n!="__stdio_common_vsprintf_s");
        if(n=="__stdio_common_vsnprintf_s" || n=="__stdio_common_vsnwprintf_s")
            return guestCrtFormat(memory,rcx,rdx,r8,arg5,arg6,arg7,rax,true,r9,true,n=="__stdio_common_vsnwprintf_s");
        if(n=="__stdio_common_vsprintf")
            return guestCrtFormat(
                memory,rcx,rdx,r8,r9,
                arg5,arg6,rax);

        using F=GuestMemory64::Fault;
        if(address>=StubBase+0x1c00 && address<StubBase+0x1cb0){
            if(!fp)return false;
            double x;std::memcpy(&x,fp->data(),8);double v=0;
            if(n=="sqrtf"){float f;std::memcpy(&f,fp->data(),4);f=std::sqrt(f);std::memcpy(fp->data(),&f,4);return true;}
            if(n=="_dsign"||n=="_ldsign"){rax=std::signbit(x)?0x8000:0;return true;}
            if(n=="_isnan"){rax=std::isnan(x);return true;}
            if(n=="ceil")v=std::ceil(x);
            if(n=="cosh")v=std::cosh(x);
            if(n=="expm1")v=std::expm1(x);
            if(n=="floor")v=std::floor(x);
            if(n=="log1p")v=std::log1p(x);
            if(n=="sinh")v=std::sinh(x);
            if(n=="sqrt")v=std::sqrt(x);
            std::memcpy(fp->data(),&v,8);return true;
        }
        if(address>=StubBase+0x1cb0 && address<StubBase+0x1d30){
            if(n=="isupper"||n=="iswalnum"||n=="iswdigit"||n=="iswspace"||n=="iswxdigit"){
                auto c=uint32_t(rcx);bool upper=c>='A'&&c<='Z',lower=c>='a'&&c<='z',digit=c>='0'&&c<='9';
                rax=n=="isupper"?upper:n=="iswalnum"?(upper||lower||digit):n=="iswdigit"?digit:n=="iswspace"?(c==32||(c>=9&&c<=13)):(digit||(c>='A'&&c<='F')||(c>='a'&&c<='f'));return true;
            }
            auto get=[&](uint64_t base,uint64_t i,unsigned unit,uint16_t& c){std::array<uint8_t,2>b{};if(i>(UINT64_MAX-base)/unit||memory.read(base+i*unit,std::span<uint8_t>(b).first(unit))!=F::none)return false;c=b[0]|uint16_t(b[1])<<8;return true;};
            if(n=="wcsnlen"||n=="__strncnt"){unsigned unit=n=="wcsnlen"?2:1;for(uint64_t i=0;i<rdx&&i<1048576;++i){uint16_t c;if(!get(rcx,i,unit,c))return false;if(!c){rax=i;return true;}}if(rdx>1048576)return false;rax=rdx;return true;}
            if(n=="strspn"){std::array<bool,256> set{};bool end=false;for(uint64_t i=0;i<1048576;++i){uint16_t c;if(!get(rdx,i,1,c))return false;if(!c){end=true;break;}set[c]=true;}if(!end)return false;for(uint64_t i=0;i<1048576;++i){uint16_t c;if(!get(rcx,i,1,c))return false;if(!c||!set[c]){rax=i;return true;}}return false;}
        }
        if(address>=StubBase+0x1800 && address<StubBase+0x1800+v82Names.size()*16)
            return dispatchV82(n,memory,rcx,rdx,r8,r9,arg5,arg6,arg7,rax);
        if((address>=StubBase+0x1120 && address<StubBase+0x11e0) || (n=="CloseHandle" && guestFiles.windowsHandle(rcx)))
            return guestFiles.winCall(n,memory,rcx,rdx,r8,r9,arg5,arg6,arg7,rax,lastError);
        if(address>=StubBase+0x11e0 && address<=StubBase+0x1210)
            return guestFiles.call(n,memory,rcx,rdx,r8,r9,rax,CrtBase+24);
        if(address==StubBase+0x1220){
            std::array<char,65> text{};
            rax=UINT32_MAX;
            if(!rcx)return true;
            for(size_t i=0;i<text.size()-1;++i){
                if(i>UINT64_MAX-rcx || memory.read(rcx+i,{reinterpret_cast<uint8_t*>(&text[i]),1})!=F::none)return false;
                if(!text[i]){
                    in_addr ip{};
                    if(inet_aton(text.data(),&ip))rax=ip.s_addr;
                    return true;
                }
            }
            return true;
        }
        if(address==StubBase+0x1230){rax=lastError;return true;}
        if(address==StubBase+0x1240){
            uint64_t count=0;
            if(!ScarlettRuntime64::readValue(memory,rdx,4,count) || count>65536 ||
               rdx>UINT64_MAX-8-8*count)return false;
            rax=0;
            for(uint64_t i=0;i<count;++i){
                uint64_t socket=0;
                if(!ScarlettRuntime64::readValue(memory,rdx+8+8*i,8,socket))return false;
                if(socket==rcx){rax=1;break;}
            }
            return true;
        }
        if(n=="GetSystemTime" || n=="GetLocalTime"){
            using namespace std::chrono;
            const auto now=system_clock::now();
            const auto seconds=floor<std::chrono::seconds>(now);
            const auto t=system_clock::to_time_t(seconds);
            std::tm date{};
            if(!gmtime_r(&t,&date))return false;
            std::array<uint16_t,8> fields={uint16_t(date.tm_year+1900),uint16_t(date.tm_mon+1),
                uint16_t(date.tm_wday),uint16_t(date.tm_mday),uint16_t(date.tm_hour),uint16_t(date.tm_min),
                uint16_t(date.tm_sec),uint16_t(duration_cast<milliseconds>(now-seconds).count())};
            return memory.write(rcx,{reinterpret_cast<const uint8_t*>(fields.data()),sizeof(fields)})==F::none;
        }
        if(n=="MFGetSystemTime"){
            rax=std::chrono::duration_cast<std::chrono::duration<int64_t,std::ratio<1,10000000>>>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            return true;
        }
        // Conservative guest capability profile: no complete optional ISA
        // feature groups or Windows fast-fail facility are implemented yet.
        if(n=="IsProcessorFeaturePresent") {rax=0;return true;}
        if(n=="htons" || n=="#9" || n=="ntohs" || n=="#15") { rax=__builtin_bswap16(uint16_t(rcx)); return true; }
        if(n=="htonl" || n=="#8" || n=="ntohl" || n=="#14") { rax=__builtin_bswap32(uint32_t(rcx)); return true; }
        if(n=="FileTimeToSystemTime" || n=="SystemTimeToFileTime") {
            const auto error=convertGuestTime(memory,rcx,rdx,n=="FileTimeToSystemTime");
            rax=error==0;
            if (error) lastError=error;
            return true;
        }
        if(address>=StubBase+0xf10 && address<StubBase+0xfc0)
            return guestFiles.call(n,memory,rcx,rdx,r8,r9,rax,CrtBase+24);
        if(n=="_difftime64") {
            if (!fp) return false;
            double seconds=0;
            if (int64_t(rcx)<=0 || int64_t(rdx)<=0) {
                if (handlers["_set_invalid_parameter_handler"]) return false;
                if (memory.write(CrtBase+24,std::array<uint8_t,4>{22,0,0,0})!=F::none) return false;
            } else seconds=rcx>=rdx ? double(rcx-rdx) : -double(rdx-rcx);
            std::memcpy(fp->data(),&seconds,sizeof(seconds));
            return true;
        }
        if(n=="GetCurrentThreadStackLimits") {
            uint64_t low=0,high=0;
            if (!ScarlettRuntime64::readValue(memory,activeTeb+0x10,8,low) ||
                !ScarlettRuntime64::readValue(memory,activeTeb+8,8,high) ||
                memory.check(rcx,8,GuestMemory64::Write)!=F::none ||
                memory.check(rdx,8,GuestMemory64::Write)!=F::none) return false;
            return ScarlettRuntime64::put64(memory,rcx,low) && ScarlettRuntime64::put64(memory,rdx,high);
        }
        if(n=="_ftime64") {
            const auto ms=std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            const int64_t seconds=ms/1000;
            const uint16_t fraction=ms%1000;
            std::array<uint8_t,16> output{};
            std::memcpy(output.data(),&seconds,8);
            std::memcpy(output.data()+8,&fraction,2);
            return memory.write(rcx,output)==F::none;
        }
        if(n=="_gmtime64_s" || n=="_localtime64_s") {
            int64_t value=0;
            std::array<int32_t,9> fields;
            if (!rcx || !rdx || memory.read(rdx,std::span<uint8_t>(reinterpret_cast<uint8_t*>(&value),8))!=F::none) return false;
            const std::time_t timestamp=value;
            std::tm date{};
            if (value<0 || value>32535215999LL || !gmtime_r(&timestamp,&date)) {
                if (handlers["_set_invalid_parameter_handler"] ||
                    memory.write(CrtBase+24,std::array<uint8_t,4>{22,0,0,0})!=F::none)return false;
                fields.fill(-1);
                rax=22;
            } else {
                fields={date.tm_sec,date.tm_min,date.tm_hour,date.tm_mday,date.tm_mon,date.tm_year,date.tm_wday,date.tm_yday,0};
                rax=0;
            }
            return memory.write(rcx,std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(fields.data()),sizeof(fields)))==F::none;
        }
        if(n=="srand") {randomState=uint32_t(rcx);return true;}
        if(n=="rand") {randomState=randomState*214013u+2531011u;rax=(randomState>>16)&0x7fffu;return true;}
        auto put=[&](uint64_t a,uint64_t v){std::array<uint8_t,8> b{}; for(unsigned i=0;i<8;++i)b[i]=uint8_t(v>>(8*i)); return memory.write(a,b)==F::none;};
        if(n=="_fdtest"||n=="_dtest") {
            double v;
            if(n=="_dtest"){std::array<uint8_t,8> raw{};if(memory.read(rcx,raw)!=F::none)return false;std::memcpy(&v,raw.data(),8);}
            else {std::array<uint8_t,4> raw{};if(memory.read(rcx,raw)!=F::none)return false;float f;std::memcpy(&f,raw.data(),4);v=f;if(std::fpclassify(f)==FP_SUBNORMAL){rax=uint16_t(-2);return true;}}
            int code=std::isnan(v)?2:std::isinf(v)?1:v==0?0:std::fpclassify(v)==FP_SUBNORMAL?-2:-1;
            rax=uint16_t(code);return true;
        }
        if(n=="atof"||n=="strtod"||n=="strtof") {
            if(!fp)return false;
            std::string str;bool terminated=false;
            for(uint64_t j=0;j<1048576;++j){std::array<uint8_t,1> c{};if(rcx>UINT64_MAX-j||memory.read(rcx+j,c)!=F::none)return false;if(!c[0]){terminated=true;break;}str+=char(c[0]);}
            if(!terminated)return false;
            char* end=nullptr;int saved=errno;errno=0;std::array<uint8_t,16> out{};
            if(n=="strtof"){float v=std::strtof(str.c_str(),&end);std::memcpy(out.data(),&v,4);}else{double v=std::strtod(str.c_str(),&end);std::memcpy(out.data(),&v,8);}
            int err=errno;errno=saved;
            if(n!="atof"&&rdx&&!put(rdx,rcx+uint64_t(end-str.c_str())))return false;
            if(err==ERANGE){std::array<uint8_t,4> e{34,0,0,0};if(memory.write(CrtBase+24,e)!=F::none)return false;}
            *fp=out;return true;
        }
        if(n=="modf"||n=="modff"||n=="_fdsign"||n=="lroundf") {
            if(!fp)return false;
            float f;std::memcpy(&f,fp->data(),4);
            if(n=="_fdsign"){rax=std::signbit(f)?0x8000:0;return true;}
            if(n=="lroundf"){double v=std::round(double(f));if(!std::isfinite(v)||v<-2147483648.0||v>2147483647.0){rax=0x80000000u;return true;}rax=uint32_t(int32_t(v));return true;}
            std::array<uint8_t,16> out{};
            if(n=="modff"){float i;float v=std::modf(f,&i);if(memory.write(rdx,std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&i),4))!=F::none)return false;std::memcpy(out.data(),&v,4);}
            else{double d,i;std::memcpy(&d,fp->data(),8);double v=std::modf(d,&i);if(memory.write(rdx,std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&i),8))!=F::none)return false;std::memcpy(out.data(),&v,8);}
            *fp=out;return true;
        }
        if(n=="SetUnhandledExceptionFilter" || n=="_set_invalid_parameter_handler" || n=="_set_purecall_handler" || n=="__setusermatherr") {
            auto& slot=handlers[n];rax=slot;slot=rcx;return true;
        }
        if(n=="RegQueryValueExW") {
            const uint32_t root=uint32_t(rcx);
            rax=((rcx==root || rcx==(0xffffffff00000000ull|root)) && root>=0x80000000u && root<=0x80000006u)?(r8?87:2):6;return true;
        }
        if(n=="OutputDebugStringA") {
            std::string msg;for(uint64_t i=0;i<65536;++i){std::array<uint8_t,1>b{};if(rcx>UINT64_MAX-i||memory.read(rcx+i,b)!=F::none)return false;if(!b[0]){if(std::getenv("ALIEN_TRACE"))std::fprintf(stderr,"GUEST_DEBUG: %s\n",msg.c_str());return true;}msg+=char(b[0]);}return false;
        }
        if(n=="_itoa") {
            unsigned base=uint32_t(r8);if(base<2||base>36){rax=0;return true;}uint32_t v=uint32_t(rcx);bool neg=base==10&&int32_t(v)<0;if(neg)v=0u-v;std::string str;do{str+="0123456789abcdefghijklmnopqrstuvwxyz"[v%base];v/=base;}while(v);if(neg)str+='-';std::reverse(str.begin(),str.end());str+='\0';if(memory.write(rdx,std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(str.data()),str.size()))!=F::none)return false;rax=rdx;return true;
        }
        if(n=="strtok"||n=="strtok_s") {
            auto byte=[&](uint64_t a,uint8_t& v){std::array<uint8_t,1>b{};if(memory.read(a,b)!=F::none)return false;v=b[0];return true;};
            std::array<bool,256> delim{};bool end=false;for(uint64_t i=0;i<65536;++i){uint8_t v;if(rdx>UINT64_MAX-i||!byte(rdx+i,v))return false;if(!v){end=true;break;}delim[v]=true;}if(!end)return false;
            uint64_t pos=rcx;if(!pos){if(n=="strtok")pos=tokenNext;else{std::array<uint8_t,8>b{};if(memory.read(r8,b)!=F::none)return false;for(unsigned i=0;i<8;++i)pos|=uint64_t(b[i])<<(8*i);}}
            auto save=[&](uint64_t v){if(n=="strtok"){tokenNext=v;return true;}return put(r8,v);};rax=0;if(!pos)return true;
            uint8_t v=0;uint64_t count=0;while(count++<1048576){if(!byte(pos,v))return false;if(!v)return save(pos);if(!delim[v])break;if(pos==UINT64_MAX)return false;++pos;}if(count>1048576)return false;uint64_t start=pos;
            while(count++<1048576){if(!byte(pos,v))return false;if(!v){rax=start;return save(pos);}if(delim[v]){if(pos==UINT64_MAX||memory.write(pos,std::array<uint8_t,1>{0})!=F::none)return false;rax=start;return save(pos+1);}if(pos==UINT64_MAX)return false;++pos;}return false;
        }
        // Synthetic single-vCPU topology, consistent with the single-thread runtime.
        if(n=="GetLogicalProcessorInformation") {
            constexpr uint32_t required=96;
            std::array<uint8_t,4> length{};
            if(memory.read(rdx,length)!=F::none || memory.check(rdx,4,GuestMemory64::Write)!=F::none){lastError=998;rax=0;return true;}
            uint32_t capacity=0;for(unsigned j=0;j<4;++j)capacity|=uint32_t(length[j])<<(8*j);
            length={uint8_t(required),0,0,0};
            if(!rcx || capacity<required){if(memory.write(rdx,length)!=F::none)return false;lastError=122;rax=0;return true;}
            std::array<uint8_t,required> records{};
            // Windows x64 records: mask at 0, relationship at 8, union at 16.
            records[0]=1; // RelationProcessorCore, no SMT
            records[32]=1;records[40]=1; // RelationNumaNode, node zero
            records[64]=1;records[72]=3; // RelationProcessorPackage
            if(memory.check(rcx,required,GuestMemory64::Write)!=F::none){lastError=998;rax=0;return true;}
            if(memory.write(rcx,records)!=F::none || memory.write(rdx,length)!=F::none)return false;
            rax=1;return true;
        }
        if(n=="_Query_perf_counter" || n=="_Query_perf_frequency" || n=="_Xtime_get_ticks" || n=="_time64") {
            using namespace std::chrono;
            if(n=="_Query_perf_counter")rax=duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
            else if(n=="_Query_perf_frequency")rax=1000000000;
            else if(n=="_Xtime_get_ticks")rax=duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count()/100;
            else {rax=duration_cast<seconds>(system_clock::now().time_since_epoch()).count();if(rcx&&!put(rcx,rax))return false;}
            return true;
        }
        // Guest timezone is UTC; no host locale dependency.
        if(n=="FileTimeToLocalFileTime" || n=="LocalFileTimeToFileTime") {
            std::array<uint8_t,8>b{};rax=memory.read(rcx,b)==F::none && memory.write(rdx,b)==F::none;if(!rax)lastError=998;return true;
        }
        if(n=="StringFromGUID2") {
            rax=0;if(uint32_t(r8)<39)return true;
            std::array<uint8_t,16>b{};if(memory.read(rcx,b)!=F::none)return false;
            constexpr unsigned order[]={3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
            constexpr char hex[]="0123456789ABCDEF";std::string str="{";
            for(unsigned i=0;i<16;++i){if(i==4||i==6||i==8||i==10)str+='-';str+=hex[b[order[i]]>>4];str+=hex[b[order[i]]&15];}str+='}';
            std::array<uint8_t,78> out{};for(unsigned i=0;i<str.size();++i)out[i*2]=uint8_t(str[i]);if(memory.write(rdx,out)!=F::none)return false;rax=39;return true;
        }
        // Observed ABI hypothesis only: CPU-side memory profile, no GPU mapping.
        if(n=="D3D12ConfigureVirtualMemoryX") {
            std::array<uint8_t,8> b{};
            if(memory.read(rcx,b)!=F::none)return false;
            uint64_t config=0;for(unsigned j=0;j<8;++j)config|=uint64_t(b[j])<<(8*j);
            if(config!=0x400000000ULL || xboxConfigured){rax=0x80070057u;return true;}
            xboxConfigured=true;rax=0;
            std::fprintf(stderr,"XBOX_EXPERIMENT config accepted (CPU-only)\n");return true;
        }
        if(n=="XMemVirtualAlloc") {
            rax=0;
            const bool reserve=(rdx==(16ULL<<30) || rdx==(24ULL<<30)) && r8==0x20402000 && ((r9==0x21 && uint32_t(arg5)==4)||(r9==3 && uint32_t(arg5)==0x801));
            // CPU-only experimental backing; recognize observed flag families.
            const bool aligned=rdx && !(rdx&0xffff) && rdx<=(4ULL<<30);
            const bool commit=aligned && r8==0x20003000 && ((r9==0x183 && uint32_t(arg5)==0x22004)||(r9==0x283 && uint32_t(arg5)==0x2404));
            // New observed allocation family; fifth argument semantics remain unknown.
            const bool extra=aligned && r8==0x20403000 && r9==0x181 && arg5!=UINT64_MAX;
            if(!xboxConfigured || rcx || !(reserve||commit||extra)) {
                std::fprintf(stderr,"XBOX_EXPERIMENT rejected size=%llx flags=%llx protection=%llx arg5=%llx\n",(unsigned long long)rdx,(unsigned long long)r8,(unsigned long long)r9,(unsigned long long)arg5);return true;
            }
            if(xboxNext>xboxLimit-rdx)return true;
            if(memory.mapSparse(xboxNext,rdx,GuestMemory64::Read|GuestMemory64::Write)!=F::none)return true;
            rax=xboxNext;xboxNext+=rdx;
            std::fprintf(stderr,"XBOX_EXPERIMENT sparse base=%llx size=%llx flags=%llx arg5=%x\n",(unsigned long long)rax,(unsigned long long)rdx,(unsigned long long)r8,uint32_t(arg5));return true;
        }
        // Isolated, empty guest registry. Root keys exist; no host registry access.
        if(n=="RegOpenKeyW" || n=="RegCloseKey") {
            const uint32_t root=uint32_t(rcx);
            const bool validRoot=(rcx==uint64_t(root) || rcx==(0xffffffff00000000ull|root)) && root>=0x80000000u && root<=0x80000006u;
            if(!validRoot){rax=6;return true;}
            if(n=="RegCloseKey"){rax=0;return true;}
            if(!r8){rax=87;return true;}
            if(rdx){
                bool nonempty=false,terminated=false;
                for(unsigned j=0;j<32768;++j){
                    std::array<uint8_t,2> b{};
                    if(rdx>UINT64_MAX-2ull*j || memory.read(rdx+2ull*j,b)!=F::none)return false;
                    if(!b[0]&&!b[1]){terminated=true;break;}
                    nonempty=true;
                }
                if(!terminated){rax=87;return true;}
                if(nonempty){rax=2;return true;}
            }
            if(!put(r8,0xffffffff00000000ull|root))return false;
            rax=0;return true;
        }
        if(n=="CreateSemaphoreExW" || n=="CreateSemaphoreW") {
            if(rcx || r9 || (n=="CreateSemaphoreExW" && uint32_t(arg5)!=0))return false;
            if(n=="CreateSemaphoreExW" && arg6!=UINT64_MAX && (uint32_t(arg6)&~0x1f0003u)){lastError=5;rax=0;return true;}
            if(int32_t(rdx)<0 || int32_t(r8)<=0 || uint32_t(rdx)>uint32_t(r8)){lastError=87;rax=0;return true;}
            if(events.size()+semaphores.size()>=65536 || nextEvent==UINT64_MAX){lastError=8;rax=0;return true;}
            rax=nextEvent++;semaphores.emplace(rax,std::pair{uint32_t(rdx),uint32_t(r8)});return true;
        }
        if(n=="ReleaseSemaphore") {
            auto e=semaphores.find(rcx);
            if(e==semaphores.end()){lastError=6;rax=0;return true;}
            auto& [count,maximum]=e->second;
            if(int32_t(rdx)<=0){lastError=87;rax=0;return true;}
            if(uint32_t(rdx)>maximum-count){lastError=298;rax=0;return true;}
            if(r8){std::array<uint8_t,4>b{};for(unsigned j=0;j<4;++j)b[j]=uint8_t(count>>(8*j));if(memory.write(r8,b)!=F::none)return false;}
            count+=uint32_t(rdx);rax=1;return true;
        }
        // Thread handles remain signaled after normal termination.
        if(n=="WaitForSingleObject" ||
           n=="WaitForSingleObjectEx"){
            auto thread=threadHandles.find(rcx);

            if(thread!=threadHandles.end()){
                if(n=="WaitForSingleObjectEx" && uint32_t(r8))
                    return false;

                uint32_t code=259;

                if(!threadExitQuery ||
                   !threadExitQuery(thread->second,code)){
                    lastError=6;
                    rax=UINT32_MAX;
                    return true;
                }

                if(threadFinishedQuery &&
                   threadFinishedQuery(thread->second)){
                    rax=0;
                    return true;
                }

                if(uint32_t(rdx)==0){
                    rax=258;
                    return true;
                }

                if(!cooperativeWaits || waitPending)
                    return false;

                pendingWait={rcx,uint32_t(rdx)};
                waitPending=true;
                return true;
            }
        }

        if(auto e=semaphores.find(rcx);e!=semaphores.end()) {
            if(n=="CloseHandle"){semaphores.erase(e);rax=1;return true;}
            if(n=="WaitForSingleObject" || n=="WaitForSingleObjectEx") {
                if(n=="WaitForSingleObjectEx" && uint32_t(r8))return false;
                if(e->second.first){--e->second.first;rax=0;return true;}
                if(uint32_t(rdx)){
                    if(!cooperativeWaits || waitPending)
                        return false;

                    pendingWait={rcx,uint32_t(rdx)};
                    waitPending=true;
                    return true;
                }
                rax=258;return true;
            }
        }
        // Single-thread event objects. Never fabricate a successful blocking wait.
        if(n=="CreateEventA" || n=="CreateEventW") {
            if(rcx || r9)return false; // security attributes and named objects not implemented
            if(events.size()>=65536 || nextEvent==UINT64_MAX){lastError=8;rax=0;return true;}
            rax=nextEvent++;events.emplace(rax,Event{uint32_t(rdx)!=0,uint32_t(r8)!=0});return true;
        }
        if(n=="CloseHandle" && threadHandles.contains(rcx)){
            threadHandles.erase(rcx);
            rax=1;return true;
        }
        if(n=="SetEvent" || n=="ResetEvent" || n=="CloseHandle" || n=="WaitForSingleObject" || n=="WaitForSingleObjectEx") {
            auto e=events.find(rcx);const bool wait=n.starts_with("WaitFor");
            if(e==events.end()){lastError=6;rax=wait?UINT32_MAX:0;return true;}
            if(n=="CloseHandle"){events.erase(e);rax=1;return true;}
            if(!wait){e->second.signaled=n=="SetEvent";rax=1;return true;}
            if(n=="WaitForSingleObjectEx" && uint32_t(r8))return false;
            if(e->second.signaled){if(!e->second.manual)e->second.signaled=false;rax=0;return true;}
            if(uint32_t(rdx)!=0){
                if(!cooperativeWaits || waitPending)
                    return false;

                pendingWait={rcx,uint32_t(rdx)};
                waitPending=true;
                return true;
            }
            rax=258;return true;
        }
        if(n=="WaitForMultipleObjects") {
            if(!uint32_t(rcx) || uint32_t(rcx)>64){lastError=87;rax=UINT32_MAX;return true;}
            std::vector<uint64_t> handles;unsigned first=64;bool all=true;
            for(unsigned i=0;i<uint32_t(rcx);++i){std::array<uint8_t,8>b{};if(rdx>UINT64_MAX-i*8 || memory.read(rdx+i*8,b)!=F::none)return false;uint64_t h=0;for(unsigned j=0;j<8;++j)h|=uint64_t(b[j])<<(8*j);if((!events.contains(h)&&!semaphores.contains(h))||std::find(handles.begin(),handles.end(),h)!=handles.end()){lastError=87;rax=UINT32_MAX;return true;}handles.push_back(h);if(events.contains(h)?events.at(h).signaled:semaphores.at(h).first!=0){if(first==64)first=i;}else all=false;}
            if(uint32_t(r8)?all:first!=64){for(unsigned i=0;i<handles.size();++i)if(uint32_t(r8)||i==first){if(auto sem=semaphores.find(handles[i]);sem!=semaphores.end())--sem->second.first;else {auto& e=events.at(handles[i]);if(!e.manual)e.signaled=false;}}rax=uint32_t(r8)?0:first;return true;}
            if(uint32_t(r9)!=0)return false;
            rax=258;return true;
        }
        if(n=="SleepConditionVariableCS") {
            auto c=criticalSections.find(rdx);std::array<uint8_t,8>b{};
            if(c==criticalSections.end() || c->second.first!=1 || memory.read(rcx,b)!=F::none || std::any_of(b.begin(),b.end(),[](auto v){return v!=0;}))return false;
            if(uint32_t(r8)!=0)return false;
            lastError=1460;rax=0;return true;
        }
        if(n=="SetLastError") {lastError=uint32_t(rcx);return true;}
        // C locale character classification and bounded guest string operations.
        if(n=="isalnum" || n=="isalpha" || n=="isdigit" || n=="islower" || n=="isspace" || n=="isxdigit") {
            uint32_t c=uint32_t(rcx);bool upper=c>=65&&c<=90,lower=c>=97&&c<=122,digit=c>=48&&c<=57;
            rax=n=="isalnum"?(upper||lower||digit):n=="isalpha"?(upper||lower):n=="isdigit"?digit:n=="islower"?lower:n=="isspace"?(c==32||(c>=9&&c<=13)):(digit||(c>=65&&c<=70)||(c>=97&&c<=102));return true;
        }
        if(n=="_stricmp" || n=="_strnicmp" || n=="_wcsnicmp" || n=="strcspn" || n=="strpbrk" || n=="wcsncpy" || n=="strncat") {
            constexpr uint64_t cap=1048576;
            unsigned unit=(n=="_wcsnicmp" || n=="wcsncpy")?2:1;
            auto get=[&](uint64_t a,uint64_t i,uint16_t& v){std::array<uint8_t,2>b{};if(a>UINT64_MAX-i*unit || memory.read(a+i*unit,std::span<uint8_t>(b).first(unit))!=F::none)return false;v=b[0]|(uint16_t(b[1])<<8);return true;};
            if(n=="strcspn" || n=="strpbrk") {
                std::array<bool,256> set{};bool ended=false;
                for(uint64_t i=0;i<cap;++i){uint16_t v;if(!get(rdx,i,v))return false;if(!v){ended=true;break;}set[v]=true;}
                if(!ended)return false;
                for(uint64_t i=0;i<cap;++i){uint16_t v;if(!get(rcx,i,v))return false;if(!v||set[v]){rax=n=="strcspn"?i:(v?rcx+i:0);return true;}}return false;
            }
            if(n=="wcsncpy" || n=="strncat") {
                if(r8>cap)return false;
                uint64_t off=0;uint16_t v=0;
                if(n=="strncat"){for(;off<cap;++off){if(!get(rcx,off,v))return false;if(!v)break;}if(off==cap)return false;}
                std::vector<uint8_t> out;bool ended=false;
                for(uint64_t i=0;i<r8;++i){v=0;if(!ended&&!get(rdx,i,v))return false;if(!v){ended=true;if(n=="strncat")break;}out.push_back(uint8_t(v));if(unit==2)out.push_back(uint8_t(v>>8));}
                if(n=="strncat")out.push_back(0);
                if(rcx>UINT64_MAX-off || memory.write(rcx+off,out)!=F::none)return false;
                rax=rcx;return true;
            }
            uint64_t limit=n=="_stricmp"?UINT64_MAX:r8;
            auto fold=[](uint16_t c){return c>=65&&c<=90?c+32:int(c);};
            for(uint64_t i=0;i<limit&&i<cap;++i){uint16_t a,b;if(!get(rcx,i,a)||!get(rdx,i,b))return false;int d=fold(a)-fold(b);if(d||!a){rax=uint32_t(d);return true;}}
            if(limit<=cap){rax=0;return true;}return false;
        }
        if(n=="tolower" || n=="toupper") {uint32_t c=uint32_t(rcx);if(n=="tolower" && c>=65 && c<=90)c+=32;if(n=="toupper" && c>=97 && c<=122)c-=32;rax=c;return true;}
        if(n=="strchr" || n=="strrchr" || n=="strcpy" || n=="strncpy" || n=="strcat") {
            constexpr uint64_t cap=1048576;
            auto byte=[&](uint64_t a,uint64_t i,uint8_t& b){return a<=UINT64_MAX-i && memory.read(a+i,std::span<uint8_t>(&b,1))==F::none;};
            if(n=="strchr" || n=="strrchr") {rax=0;for(uint64_t i=0;i<cap;++i){uint8_t b;if(!byte(rcx,i,b))return false;if(b==uint8_t(rdx)){rax=rcx+i;if(n=="strchr")return true;}if(!b)return true;}return false;}
            uint64_t off=0;if(n=="strcat"){for(;off<cap;++off){uint8_t b;if(!byte(rcx,off,b))return false;if(!b)break;}if(off==cap)return false;}
            uint64_t limit=n=="strncpy"?r8:cap;if(limit>cap || rcx>UINT64_MAX-off)return false;
            std::vector<uint8_t> out;bool ended=false;for(uint64_t i=0;i<limit;++i){uint8_t b=0;if(!ended && !byte(rdx,i,b))return false;out.push_back(b);if(!b){ended=true;if(n!="strncpy")break;}}
            if(n!="strncpy" && !ended)return false;
            if(memory.write(rcx+off,out)!=F::none)return false;
            rax=rcx;return true;
        }
        if(n=="RtlVirtualUnwind") {
            // Restricted prolog-only, no handler or nonvolatile context pointers.
            if(rcx!=0 || !r9 || arg8!=0 || !arg5 || !arg6 || !arg7 || arg5==UINT64_MAX || arg6==UINT64_MAX) return false;
            if(memory.check(arg6,8,GuestMemory64::Write)!=F::none || memory.check(arg7,8,GuestMemory64::Write)!=F::none) return false;
            uint64_t frame=0;
            if(!unwindProlog64(memory,rdx,r8,r9,arg5,frame)) return false;
            if(!put(arg6,0)||!put(arg7,frame)) return false;
            rax=0;return true;
        }
        if(n=="RtlLookupFunctionEntry") {
            rax=0;
            if(!imageBase || rcx<imageBase || rcx-imageBase>=imageSize) return true;
            if(!put(rdx,imageBase)) return false;
            if(!exceptionSize) return true;
            if(exceptionSize%12 || exceptionRva>imageSize || exceptionSize>imageSize-exceptionRva) return false;
            uint32_t lo=0,hi=exceptionSize/12;
            const uint64_t pc=rcx-imageBase;
            while(lo<hi){
                uint32_t mid=lo+(hi-lo)/2;
                uint64_t at=imageBase+exceptionRva+uint64_t(mid)*12;
                std::array<uint8_t,12> b{};
                if(memory.read(at,b)!=F::none) return false;
                auto u32=[&](unsigned off){uint32_t v=0;for(unsigned i=0;i<4;++i)v|=uint32_t(b[off+i])<<(8*i);return v;};
                auto begin=u32(0),end=u32(4),unwind=u32(8);
                if(begin>=end || end>imageSize || !unwind || unwind>=imageSize) return false;
                if(pc<begin) hi=mid;
                else if(pc>=end) lo=mid+1;
                else {rax=at;return true;}
            }
            return true;
        }
        if(n=="GetModuleHandleW" || n=="GetModuleHandleA" || n=="GetProcAddress") {
            auto readName=[&](uint64_t a,bool wide,std::string& out){
                unsigned unit=wide?2:1;
                for(unsigned i=0;i<1024;++i){
                    if(a>UINT64_MAX-i*unit)return false;
                    std::array<uint8_t,2>b{};
                    if(memory.read(a+i*unit,std::span<uint8_t>(b).first(unit))!=F::none)return false;
                    if(!b[0]&&!b[1])return true;
                    if(b[1])return false;
                    out.push_back(char(b[0]));
                }return false;
            };
            rax=0;
            if(n=="GetProcAddress") {
                for(const auto& [key,handle]:modules)if(handle==rcx){
                    {std::string sym;if(rdx<=65535) sym="#"+std::to_string(rdx);else if(!readName(rdx,false,sym))return false;
                        auto e=exports.at(key).find(sym);if(std::getenv("ALIEN_TRACE"))std::fprintf(stderr,"PROC module=%s symbol=%s result=%llx\n",key.c_str(),sym.c_str(),(unsigned long long)(e==exports.at(key).end()?0:e->second));if(e!=exports.at(key).end()){rax=e->second;return true;}}
                    if(std::getenv("ALIEN_TRACE")){std::fprintf(stderr,"PROC missing module=%s\n",key.c_str());}lastError=127;return true;
                }
                lastError=6;return true;
            }
            if(!rcx){rax=imageBase;if(!rax)lastError=126;return true;}
            std::string key;if(!readName(rcx,n=="GetModuleHandleW",key))return false;
            key=normalize(key);if(key.find('.')==std::string::npos)key+=".dll";
            auto m=modules.find(key);if(m!=modules.end())rax=m->second;else lastError=126;
            if(std::getenv("ALIEN_TRACE")) std::fprintf(stderr,"MODULE name=%s result=%llx\n",key.c_str(),(unsigned long long)rax);
            return true;
        }
        // Single-thread HLE: no guest scheduler or blocking waits yet.
        if(n=="InitializeConditionVariable" || n=="WakeConditionVariable" || n=="WakeAllConditionVariable" || n.find("SRWLock")!=std::string::npos) {
            if(!rcx || rcx%8 || memory.check(rcx,8,GuestMemory64::Read|GuestMemory64::Write)!=F::none)return false;
            std::array<uint8_t,8>b{};
            if(n=="InitializeConditionVariable" || n=="InitializeSRWLock")return memory.write(rcx,b)==F::none;
            if(memory.read(rcx,b)!=F::none)return false;
            uint64_t v=0;for(unsigned i=0;i<8;++i)v|=uint64_t(b[i])<<(8*i);
            if(n=="WakeConditionVariable" || n=="WakeAllConditionVariable")return v==0;
            bool shared=n.ends_with("Shared"), attempt=n.starts_with("Try"), releaseLock=n.starts_with("Release");
            if(releaseLock){if(shared?(v==0 || v==UINT64_MAX):v!=UINT64_MAX)return false;v=shared?v-1:0;}
            else {if(shared?v>=UINT64_MAX-1:v!=0){if(attempt){rax=0;return true;}return false;}v=shared?v+1:UINT64_MAX;}
            for(unsigned i=0;i<8;++i)b[i]=uint8_t(v>>(8*i));
            if(memory.write(rcx,b)!=F::none)return false;
            if(attempt)rax=1;
            return true;
        }
        // Synthetic single-thread RTL_CRITICAL_SECTION (40-byte x64 layout).
        if(n=="InitializeCriticalSectionEx" || n=="InitializeCriticalSectionAndSpinCount" || n=="InitializeCriticalSection" || n=="EnterCriticalSection" || n=="LeaveCriticalSection" || n=="DeleteCriticalSection" || n=="TryEnterCriticalSection") {
            if(!rcx || rcx%8 || memory.check(rcx,40,GuestMemory64::Read|GuestMemory64::Write)!=F::none)return false;
            auto it=criticalSections.find(rcx);
            const bool init=n=="InitializeCriticalSectionEx" || n=="InitializeCriticalSectionAndSpinCount" || n=="InitializeCriticalSection";
            uint32_t depth=0,spin=0;
            if(init){if(it!=criticalSections.end() || criticalSections.size()>=65536)return false;if(n=="InitializeCriticalSectionEx" && (uint32_t(r8)&~0x01000000u)){lastError=87;rax=0;return true;}spin=n!="InitializeCriticalSection"?uint32_t(rdx)&0x00ffffffu:0;}
            else {if(it==criticalSections.end())return false;depth=it->second.first;spin=it->second.second;}
            if(n=="DeleteCriticalSection"){if(depth)return false;std::array<uint8_t,40>b{};if(memory.write(rcx,b)!=F::none)return false;criticalSections.erase(it);return true;}
            if(n=="EnterCriticalSection" || n=="TryEnterCriticalSection"){if(depth>=0x7fffffffu)return false;++depth;}
            if(n=="LeaveCriticalSection"){if(!depth)return false;--depth;}
            std::array<uint8_t,40>b{};
            auto field=[&](unsigned off,uint64_t v,unsigned size){for(unsigned j=0;j<size;++j)b[off+j]=uint8_t(v>>(8*j));};
            field(0,UINT64_MAX,8);field(8,depth?depth-1:UINT32_MAX,4);field(12,depth,4);field(16,depth?1:0,8);field(32,spin,8);
            if(memory.write(rcx,b)!=F::none)return false;
            criticalSections[rcx]={depth,spin};
            if(n=="InitializeCriticalSectionEx" || n=="InitializeCriticalSectionAndSpinCount" || n=="TryEnterCriticalSection")rax=1;
            return true;
        }

        if(n=="_register_thread_local_exe_atexit_callback") {
            if(!rcx ||
               memory.check(rcx,1,GuestMemory64::Execute)!=F::none)
                return false;

            if(tlsExeExitCallback)
                return false;

            tlsExeExitCallback=rcx;
            return true;
        }

        if(n=="_crt_atexit") {
            if(!rcx || memory.check(rcx,1,GuestMemory64::Execute)!=F::none || exitCallbacks.size()>=65536) {rax=UINT32_MAX;return true;}
            exitCallbacks.push_back(rcx);rax=0;return true;
        }
        if(n=="__p__commode") {rax=CrtBase;return true;}
        if(n=="__p___argc") {rax=CrtBase+8;return true;}
        if(n=="__p___argv") {rax=CrtBase+16;return true;}
        if(n=="_errno") {rax=CrtBase+24;return true;}
        if(n=="_get_narrow_winmain_command_line") {rax=CrtBase+144;return true;}
        if(n=="_initialize_narrow_environment") {rax=0;return true;} // intentionally empty synthetic environment
        if(n=="_configure_narrow_argv") {if(rcx>2)return false; if(rcx==0){std::array<uint8_t,4>b{};if(memory.write(CrtBase+8,b)!=F::none || !put(CrtBase+16,0))return false;}else{std::array<uint8_t,4>b{1,0,0,0};if(memory.write(CrtBase+8,b)!=F::none || !put(CrtBase+16,CrtBase+32))return false;}rax=0;return true;}
        if(n=="_initialize_onexit_table") {std::array<uint8_t,24>b{};if(!rcx){rax=UINT32_MAX;return true;}if(memory.write(rcx,b)!=F::none)return false;rax=0;return true;}
        auto setErrno=[&](uint32_t v){std::array<uint8_t,4>b{};for(unsigned j=0;j<4;++j)b[j]=uint8_t(v>>(8*j));return memory.write(CrtBase+24,b)==F::none;};

        // V33: bounded guest-only virtual memory and string operations.
        if(n=="GetCommandLineA"){rax=CrtBase+128;return true;}
        if(n=="IsDebuggerPresent"){rax=0;return true;}
        if(n=="GetProcessId"){rax=rcx==UINT64_MAX?1000:0;if(!rax)lastError=6;return true;}

        // V85D: FLS subset for one fiber per guest thread. Callbacks are not supported.
        if(n=="EncodePointer" || n=="DecodePointer") {rax=rcx^pointerCookie;return true;}
        if(n=="RtlPcToFileHeader") {
            rax=(imageBase && rcx>=imageBase && rcx-imageBase<imageSize)?imageBase:0;
            return put(rdx,rax);
        }
        if(n=="FlsAlloc") {
            if(rcx){lastError=50;rax=UINT32_MAX;return true;}
            for(uint32_t i=0;i<128;++i) if(flsSlots.emplace(i,0).second){rax=i;return true;}
            lastError=8;rax=UINT32_MAX;return true;
        }
        if(n=="FlsFree" || n=="FlsGetValue" || n=="FlsSetValue") {
            uint32_t slot=uint32_t(rcx);
            if(!flsSlots.contains(slot)){lastError=87;rax=0;return true;}
            if(n=="FlsFree"){flsSlots.erase(slot);for(auto& t:threadLocals)t.second.fls.erase(slot);rax=1;return true;}
            auto& values=threadLocals[activeThread].fls;
            if(n=="FlsSetValue"){values[slot]=rdx;rax=1;return true;}
            auto it=values.find(slot);lastError=0;rax=it==values.end()?0:it->second;return true;
        }
        if(n=="TlsAlloc"){
            for(uint32_t i=0;i<1088;++i){
                if(!tlsValues.contains(i)){
                    tlsValues.emplace(i,0);
                    rax=i;return true;
                }
            }
            lastError=8;rax=0xffffffffu;return true;
        }

        if(n=="TlsFree"){
            uint32_t slot=uint32_t(rcx);
            rax=tlsValues.erase(slot)?1:0;
            if(!rax){lastError=87;return true;}
            for(auto& item:threadLocals)
                item.second.values.erase(slot);
            return true;
        }

        if(n=="TlsGetValue" || n=="TlsSetValue"){
            uint32_t slot=uint32_t(rcx);
            if(!tlsValues.contains(slot)){
                lastError=87;rax=0;return true;
            }

            auto& values=threadLocals[activeThread].values;

            if(n=="TlsSetValue"){
                values[slot]=rdx;
                rax=1;return true;
            }

            auto it=values.find(slot);
            lastError=0;
            rax=it==values.end()?0:it->second;
            return true;
        }

        if(n=="GetExitCodeThread"){
            rax=0;
            uint64_t id=activeThread;

            if(rcx!=UINT64_MAX-1){
                auto it=threadHandles.find(rcx);
                if(it==threadHandles.end()){
                    lastError=6;return true;
                }
                id=it->second;
            }

            uint32_t code=259;
            if(!threadExitQuery ||
               !threadExitQuery(id,code)){
                lastError=6;return true;
            }

            std::array<uint8_t,4> b{};
            for(unsigned j=0;j<4;++j)
                b[j]=uint8_t(code>>(8*j));

            if(memory.write(rdx,b)!=F::none){
                lastError=998;return true;
            }

            rax=1;return true;
        }

        if(n=="CreateThread"){
            rax=0;
            if(!threadCreator){
                lastError=120;return true;
            }
            if(rcx || arg5!=0 || arg6==UINT64_MAX){
                lastError=87;return true;
            }
            if(arg6 && memory.check(arg6,4,GuestMemory64::Write)!=F::none){
                lastError=998;return true;
            }
            if(threadHandles.size()>=4096){
                lastError=8;return true;
            }
            uint64_t id=threadCreator(r8,r9,rdx);
            if(!id){lastError=8;return true;}
            if(arg6){
                std::array<uint8_t,4> b{};
                for(unsigned j=0;j<4;++j)
                    b[j]=uint8_t(id>>(8*j));
                if(memory.write(arg6,b)!=F::none)return false;
            }
            rax=nextThreadHandle++;
            threadHandles.emplace(rax,id);
            return true;
        }



        if(n=="GetCurrentThread"){
            rax=UINT64_MAX-1;return true;
        }

        if(n=="GetThreadId"){
            if(rcx==UINT64_MAX-1){
                rax=activeThread;return true;
            }
            auto it=threadHandles.find(rcx);
            if(it!=threadHandles.end()){
                rax=it->second;return true;
            }
            lastError=6;rax=0;return true;
        }

        if(n=="InterlockedIncrement" ||
           n=="InterlockedDecrement" ||
           n=="InterlockedExchange" ||
           n=="InterlockedExchangeAdd" ||
           n=="InterlockedCompareExchange" ||
           n=="InterlockedCompareExchange64"){

            unsigned width=
                n=="InterlockedCompareExchange64"?8:4;

            if(rcx%width ||
               memory.check(rcx,width,
                   GuestMemory64::Read|GuestMemory64::Write)
                   !=F::none)return false;

            std::array<uint8_t,8> bytes{};
            auto view=std::span<uint8_t>(bytes).first(width);

            if(memory.read(rcx,view)!=F::none)
                return false;

            uint64_t old=0;
            for(unsigned i=0;i<width;++i)
                old|=uint64_t(bytes[i])<<(8*i);

            uint64_t mask=
                width==8?UINT64_MAX:0xffffffffULL;

            uint64_t value=old;
            rax=old;

            if(n=="InterlockedIncrement"){
                value=(old+1)&mask;rax=value;
            }else if(n=="InterlockedDecrement"){
                value=(old-1)&mask;rax=value;
            }else if(n=="InterlockedExchange"){
                value=rdx&mask;
            }else if(n=="InterlockedExchangeAdd"){
                value=(old+rdx)&mask;
            }else if(old==(r8&mask)){
                value=rdx&mask;
            }

            for(unsigned i=0;i<width;++i)
                bytes[i]=uint8_t(value>>(8*i));

            return memory.write(rcx,view)==F::none;
        }

        if(n=="VirtualProtect"){
            auto decode=[](uint64_t v)->int {switch(v){case 1:return 0;case 2:return 1;case 4:return 3;case 0x10:return 4;case 0x20:return 5;case 0x40:return 7;default:return -1;}};
            constexpr uint32_t encode[]={1,2,0,4,0x10,0x20,0,0x40};
            int perm=decode(r8);rax=0;
            if(perm<0 || !rdx || rdx>UINT64_MAX-rcx || rcx+rdx>UINT64_MAX-4095){lastError=87;return true;}
            uint64_t base=rcx&~4095ull, end=(rcx+rdx+4095)&~4095ull;
            // Restrict protection to a single tracked VirtualAlloc allocation.
            bool found=false;
            for(const auto& [a,size]:virtualBlocks){(void)size;auto span=blocks.at(a).second;if(base>=a && end-a<=span){found=true;break;}}

            for(const auto& [a,n]:lifecycleBlocks)
                if(base>=a && base-a<=n &&
                   end-base<=n-(base-a)){
                    found=true;break;
                }
            if(!found){lastError=487;return true;}
            // Output must remain writable after the protection change.
            if(memory.check(r9,4,GuestMemory64::Write)!=F::none || r9>UINT64_MAX-4 || (r9<end && r9+4>base)){lastError=998;return true;}
            uint8_t old=0;
            if(memory.protect(base,end-base,uint8_t(perm),old)!=F::none){lastError=487;return true;}
            uint32_t value=encode[old];std::array<uint8_t,4> out{};
            for(unsigned j=0;j<4;++j)out[j]=uint8_t(value>>(8*j));
            if(memory.write(r9,out)!=F::none)return false;
            rax=1;return true;
        }

        // V80 virtual lifecycle
        if(n=="VirtualAlloc"){
            rax=0;
            constexpr uint64_t cap=64ULL<<30;

            int perm=-1;
            switch(r9){
                case 1:perm=0;break;
                case 2:perm=1;break;
                case 4:perm=3;break;
                case 0x10:perm=4;break;
                case 0x20:perm=5;break;
                case 0x40:perm=7;break;
            }

            if(!rdx || rdx>cap || perm<0 ||
               (r8!=0x1000 && r8!=0x2000 &&
                r8!=0x3000)){
                lastError=87;return true;
            }

            bool reserve=(r8&0x2000)!=0;
            bool commit=(r8&0x1000)!=0;
            uint64_t base=rcx;
            uint64_t span=0;

            if(rcx){
                base=rcx&~(reserve?65535ULL:4095ULL);
                if(rdx>UINT64_MAX-rcx ||
                   rcx+rdx>UINT64_MAX-4095){
                    lastError=87;return true;
                }
                span=((rcx+rdx+4095)&~4095ULL)-base;
            }else{
                span=(rdx+4095)&~4095ULL;
                reserve=true;

                const uint64_t limit=virtualLimit;
                if(virtualNext>limit-65535){
                    lastError=8;return true;
                }
                base=(virtualNext+65535)&~65535ULL;
                if(span>limit-base){
                    lastError=8;return true;
                }

            }

            if(!span || span>cap ||
               span>UINT64_MAX-base){
                lastError=87;return true;
            }

            if(reserve){
                if(memory.reserve(base,span)!=F::none){
                    lastError=487;return true;
                }
                lifecycleBlocks.emplace(base,span);
            }

            if(commit){
                bool found=false;
                for(const auto& [a,n]:lifecycleBlocks)
                    if(base>=a && base-a<=n &&
                       span<=n-(base-a)){
                        found=true;break;
                    }

                if(!found ||
                   memory.commit(base,span,uint8_t(perm))
                       !=F::none){
                    if(reserve){
                        memory.releaseReservation(base);
                        lifecycleBlocks.erase(base);
                    }
                    lastError=487;return true;
                }
            }

            if(!rcx)virtualNext=base+span;
            rax=base;return true;
        }

        if(n=="VirtualFree"){
            rax=0;

            if(r8==0x8000){
                if(rdx){
                    lastError=87;return true;
                }

                if(lifecycleBlocks.contains(rcx)){
                    if(memory.releaseReservation(rcx)
                        !=F::none){
                        lastError=487;return true;
                    }
                    lifecycleBlocks.erase(rcx);
                    rax=1;return true;
                }

                if(virtualBlocks.contains(rcx)){
                    if(!release(memory,rcx))return false;
                    virtualBlocks.erase(rcx);
                    rax=1;return true;
                }
            }

            if(r8==0x4000 && rdx &&
               rdx<=UINT64_MAX-rcx &&
               rcx+rdx<=UINT64_MAX-4095){

                uint64_t base=rcx&~4095ULL;
                uint64_t end=(rcx+rdx+4095)&~4095ULL;

                for(const auto& [a,n]:lifecycleBlocks){
                    if(base>=a && base-a<=n &&
                       end-base<=n-(base-a)){
                        if(memory.decommit(base,end-base)
                            ==F::none){
                            rax=1;return true;
                        }
                    }
                }
            }

            lastError=87;return true;
        }
        if(n=="strstr"||n=="wcsrchr"||n=="strcpy_s"||n=="strcat_s"||n=="strncpy_s"||n=="wcscat_s"){
            const bool wide=n=="wcsrchr"||n=="wcscat_s";
            const uint64_t unit=wide?2:1, cap=1048576;
            auto readString=[&](uint64_t a,std::vector<uint16_t>& out,uint64_t limit){for(uint64_t j=0;j<limit;++j){std::array<uint8_t,2>b{};if(a>UINT64_MAX-j*unit||memory.read(a+j*unit,std::span<uint8_t>(b).first(unit))!=F::none)return false;uint16_t v=uint16_t(b[0])|(uint16_t(b[1])<<8);if(!v)return true;out.push_back(v);}return limit<cap;};
            std::vector<uint16_t>a,b;
            if(n=="strstr"||n=="wcsrchr"){
                if(!readString(rcx,a,cap))return false;
                if(n=="wcsrchr"){rax=0;if(!uint16_t(rdx)){rax=rcx+a.size()*2;return true;}for(size_t j=0;j<a.size();++j)if(a[j]==uint16_t(rdx))rax=rcx+j*2;return true;}
                if(!readString(rdx,b,cap))return false;
                if(n=="strstr"){auto it=std::search(a.begin(),a.end(),b.begin(),b.end());rax=b.empty()?rcx:it==a.end()?0:rcx+uint64_t(it-a.begin());return true;}
                return false;
            }
            if(!rcx||!rdx||rdx>cap){rax=22;return setErrno(22);}
            auto fail=[&](uint32_t e){std::array<uint8_t,2>z{};rax=e;return memory.write(rcx,std::span<const uint8_t>(z).first(unit))==F::none&&setErrno(e);};
            if(!r8)return fail(22);
            if(n=="strcat_s"||n=="wcscat_s"){if(!readString(rcx,a,rdx))return fail(22);if(a.size()>=rdx)return fail(22);}
            const bool trunc=n=="strncpy_s"&&r9==UINT64_MAX;
            uint64_t lim=n=="strncpy_s"&&!trunc?std::min(r9,cap):cap;
            if(!readString(r8,b,lim))return false;
            if(a.size()+b.size()>=rdx){if(!trunc)return fail(34);b.resize(rdx-1);rax=80;}else rax=0;
            a.insert(a.end(),b.begin(),b.end());a.push_back(0);std::vector<uint8_t> bytes;for(auto c:a){bytes.push_back(uint8_t(c));if(wide)bytes.push_back(uint8_t(c>>8));}return memory.write(rcx,bytes)==F::none;
        }
        if(n=="_strtoi64"||n=="_strtoui64"||n=="atoi"||n=="atol"||n=="atoll"||n=="strtol"||n=="strtoll"||n=="strtoul"||n=="strtoull") {
            const bool simple=n=="atoi"||n=="atol"||n=="atoll", uns=n=="_strtoui64"||n=="strtoul"||n=="strtoull", narrow=n=="atol"||n=="atoi"||n=="strtol"||n=="strtoul";
            int base=simple?10:int32_t(r8);if(base!=0&&(base<2||base>36)){rax=0;return setErrno(22);}
            std::string str;bool ended=false;for(uint64_t i=0;i<1048576;++i){std::array<uint8_t,1>b{};if(rcx>UINT64_MAX-i||memory.read(rcx+i,b)!=F::none)return false;if(!b[0]){ended=true;break;}str.push_back(char(b[0]));}if(!ended)return false;
            size_t j=0;while(j<str.size()&&(str[j]==' '||(str[j]>=9&&str[j]<=13)))++j;bool neg=false;if(j<str.size()&&(str[j]=='+'||str[j]=='-')){neg=str[j]=='-';++j;}
            auto digit=[](unsigned char c)->unsigned{return c>='0'&&c<='9'?c-'0':c>='a'&&c<='z'?c-'a'+10:c>='A'&&c<='Z'?c-'A'+10:99;};
            if((base==0||base==16)&&j+2<str.size()&&str[j]=='0'&&(str[j+1]=='x'||str[j+1]=='X')&&digit(str[j+2])<16){base=16;j+=2;}if(!base)base=j<str.size()&&str[j]=='0'?8:10;
            size_t start=j;uint64_t max=uns?(narrow?UINT32_MAX:UINT64_MAX):(narrow?uint64_t(INT32_MAX):uint64_t(INT64_MAX))+unsigned(neg),v=0;bool overflow=false;
            for(;j<str.size();++j){unsigned d=digit(str[j]);if(d>=unsigned(base))break;if(v>(max-d)/unsigned(base)){overflow=true;v=max;}else if(!overflow)v=v*unsigned(base)+d;}
            if(j==start){j=0;v=0;neg=false;}if(overflow&&!setErrno(34))return false;if(!simple&&rdx&&!put(rdx,rcx+j))return false;
            rax=neg&&!(uns&&overflow)?uint64_t(0)-v:v;if(narrow)rax=uint32_t(rax);return true;
        }
        if(n=="_configthreadlocale") {const auto mode=uint32_t(rcx); if(mode>2){if(!setErrno(22))return false;rax=UINT32_MAX;}else{rax=localeMode;if(mode)localeMode=mode;}return true;}
        if(n=="_set_fmode") { auto v=uint32_t(rcx); if(v!=0x4000 && v!=0x8000 && v!=0x40000){if(!setErrno(22))return false;rax=22;}else{fileMode=v;rax=0;}return true; }
        if(n=="_set_new_mode") {auto v=uint32_t(rcx);if(v>1){if(!setErrno(22))return false;rax=UINT32_MAX;}else{rax=newMode;newMode=v;}return true;}
        if(n=="_set_errno") {if(!setErrno(uint32_t(rcx)))return false;rax=0;return true;}
        if(n=="_get_errno") {std::array<uint8_t,4> b{};if(memory.read(CrtBase+24,b)!=F::none)return false;if(!rcx){rax=22;return true;}if(memory.write(rcx,b)!=F::none)return false;rax=0;return true;}
        if(n=="wcscoll" || n=="_wcsicoll" || n=="lstrcmpW" || n=="strlen" || n=="wcslen" || n=="strcmp" || n=="strncmp" || n=="wcscmp" || n=="wcsncmp") {
            const bool wide=n=="wcscoll" || n=="_wcsicoll" || n=="lstrcmpW" || n=="wcslen" || n=="wcscmp" || n=="wcsncmp", length=n=="strlen" || n=="wcslen";
            const uint64_t unit=wide?2:1, limit=(n=="strncmp" || n=="wcsncmp")?r8:UINT64_MAX;
            auto get=[&](uint64_t base,uint64_t i,uint16_t& v){if(base>UINT64_MAX-i*unit)return false;std::array<uint8_t,2>b{};if(memory.read(base+i*unit,std::span<uint8_t>(b).first(unit))!=F::none)return false;v=uint16_t(b[0])|(uint16_t(b[1])<<8);return true;};
            for(uint64_t j=0;j<limit && j<1048576;++j){uint16_t a=0,b=0;if(!get(rcx,j,a))return false;if(length){if(!a){rax=j;return true;}}else{if(!get(rdx,j,b))return false;if(n=="_wcsicoll"){if(a>=65&&a<=90)a+=32;if(b>=65&&b<=90)b+=32;}if(a!=b || !a){rax=uint32_t(int(a)-int(b));return true;}}}
            if(limit<=1048576){rax=0;return true;}return false;
        }
        if(n=="_set_app_type") { if(rcx>2) return false; appType=uint32_t(rcx); return true; }
        if(n=="GetCurrentProcess") {rax=UINT64_MAX;return true;}
        if(n=="GetLastError") {rax=lastError;return true;}
        if(n=="QueryPerformanceFrequency") {rax=put(rcx,1000000000)?1:0; if(!rax)lastError=998;return true;}
        if(n=="GetTickCount64") {rax=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();return true;}
        // Serialized guest scheduler: x64 16-byte SLIST header, depth and sequence.
        if(n=="InterlockedPushEntrySList" || n=="InterlockedFlushSList" || n=="InterlockedPopEntrySList" || n=="QueryDepthSList") {
            uint64_t lo=0,hi=0;
            if(rcx%16 || !ScarlettRuntime64::readValue(memory,rcx,8,lo) || !ScarlettRuntime64::readValue(memory,rcx+8,8,hi)) return false;
            uint64_t head=hi&~15ull, next=head; uint16_t count=uint16_t(lo);
            if(n=="QueryDepthSList"){rax=count;return true;}
            if(memory.check(rcx,16,GuestMemory64::Write)!=F::none)return false;
            if(n=="InterlockedPushEntrySList"){
                if(!rdx || rdx%16 || rdx==rcx || rdx==head || !put(rdx,head))return false;
                next=rdx; ++count;
            }else if(n=="InterlockedPopEntrySList"){
                if(!head){rax=0;return true;}
                if(!ScarlettRuntime64::readValue(memory,head,8,next) || next%16)return false;
                --count;
            }else{if(!head){rax=0;return true;}next=0;count=0;}
            uint64_t newlo=((lo+0x10000ull)&~0xffffull)|count;
            std::array<uint8_t,16> b{};uint64_t newhi=next|(hi&15);
            for(unsigned j=0;j<8;++j){b[j]=uint8_t(newlo>>(8*j));b[j+8]=uint8_t(newhi>>(8*j));}
            if(memory.write(rcx,b)!=F::none)return false;rax=head;return true;
        }
        // Current-process termination is intercepted by CPU dispatch, never host exit.
        if(n=="TerminateProcess"){if(rcx==UINT64_MAX)return false;lastError=6;rax=0;return true;}
        if(n=="InitializeSListHead") {std::array<uint8_t,16> b{};return rcx%16==0 && memory.write(rcx,b)==F::none;}
        if(n=="malloc" || n=="calloc" || n=="realloc" || n=="free") {
            if(n=="free") {if(virtualBlocks.contains(rcx))return false;if(!rcx)return true;return release(memory,rcx);}
            uint64_t size=rcx;
            if(n=="calloc") {if(rdx && rcx>UINT64_MAX/rdx){rax=0;return true;}size=rcx*rdx;}
            if(n=="realloc") {if(virtualBlocks.contains(rcx))return false;size=rdx;if(rcx && !blocks.contains(rcx))return false;if(rcx && !size){if(!release(memory,rcx))return false;rax=0;return true;}}
            if(n=="realloc" && rcx && size<=blocks.at(rcx).second){blocks.at(rcx).first=size;rax=rcx;return true;}
            rax=allocate(memory,size);
            if(rax && n=="realloc" && rcx) {std::vector<uint8_t> b(std::min(size,blocks.at(rcx).first));if(memory.read(rcx,b)!=F::none || memory.write(rax,b)!=F::none){release(memory,rax);return false;}if(!release(memory,rcx))return false;}
            return true;
        }
        if(n=="memcpy" || n=="memmove" || n=="memset" || n=="memcmp" || n=="memchr") {
            if(r8>16*1024*1024)return false;
            std::vector<uint8_t> b(r8);
            if(n=="memset")std::fill(b.begin(),b.end(),uint8_t(rdx));
            else if(memory.read((n=="memcmp" || n=="memchr")?rcx:rdx,b)!=F::none)return false;
            if(n=="memchr") {auto i=std::find(b.begin(),b.end(),uint8_t(rdx));rax=i==b.end()?0:rcx+uint64_t(i-b.begin());return true;}
            if(n=="memcmp") {std::vector<uint8_t> c(r8);if(memory.read(rdx,c)!=F::none)return false;rax=0;for(size_t i=0;i<b.size();++i)if(b[i]!=c[i]){rax=uint32_t(int(b[i])-int(c[i]));break;}return true;}
            if(memory.write(rcx,b)!=F::none)return false;
            rax=rcx;return true;
        }
        if (it->second == "QueryPerformanceCounter") {
            using namespace std::chrono;

            const auto ticks = duration_cast<nanoseconds>(
                steady_clock::now().time_since_epoch()
            ).count();

            const uint64_t value =
                static_cast<uint64_t>(ticks);

            std::array<uint8_t,8> bytes{};
            for (unsigned i=0; i<8; ++i)
                bytes[i] = uint8_t(value >> (i*8));

            if (memory.write(rcx, bytes) !=
                GuestMemory64::Fault::none) {
                rax = 0;
                return true;
            }

            rax = 1;
            return true;
        }

        if (it->second == "GetCurrentProcessId") {
            rax = 1000;
            return true;
        }

        if (it->second == "GetCurrentThreadId") {
            // Active cooperative guest thread ID.
            rax = activeThread;
            return true;
        }

        if ((it->second == "GetSystemTimeAsFileTime" || n=="GetSystemTimePreciseAsFileTime")) {
            using namespace std::chrono;

            const auto now =
                system_clock::now().time_since_epoch();

            const auto ticks =
                duration_cast<nanoseconds>(now).count() / 100
                + 116444736000000000LL;

            std::array<uint8_t,8> bytes{};
            const uint64_t value =
                static_cast<uint64_t>(ticks);

            for (unsigned i=0; i<8; ++i)
                bytes[i] = uint8_t(value >> (i*8));

            return memory.write(rcx, bytes) ==
                   GuestMemory64::Fault::none;
        }

        return false;
    }

    void recordMissing(uint64_t slot,const std::string& name) {missingSlots[slot]=name;}
    std::string missingName(uint64_t slot) const {auto i=missingSlots.find(slot);return i==missingSlots.end()?std::string{}:i->second;}
private:
    mutable std::unordered_map<std::string,uint64_t> handlers;
    mutable uint64_t tokenNext=0;
    mutable bool xboxConfigured=false;
    
public:
    void enableNativeXboxMemory() {
        xboxNext=GuestMemory64::DirectSparseBase;
        xboxLimit=GuestMemory64::DirectSparseLimit;
    }

private:
    uint64_t xboxLimit=0x810000000000ULL;
    mutable uint64_t xboxNext=0x800000000000ULL;
    static std::string normalize(std::string s){for(auto& c:s)if(c>='A'&&c<='Z')c=char(c-'A'+'a');return s;}
    uint64_t imageBase=0;
    uint32_t imageSize=0,exceptionRva=0,exceptionSize=0;
    DynamicLoader dynamicLoader;
    std::unordered_map<std::string,uint64_t> modules;
    std::unordered_map<std::string,std::unordered_map<std::string,uint64_t>> exports;
    mutable std::unordered_map<uint64_t,std::pair<uint32_t,uint32_t>> criticalSections;
    std::unordered_map<uint64_t,std::string> missingSlots;
    mutable std::vector<uint64_t> exitCallbacks;
    mutable uint64_t tlsExeExitCallback=0;

    struct Event {bool manual,signaled;};
    mutable std::unordered_map<uint64_t,Event> events;
    mutable std::unordered_map<uint64_t,std::pair<uint32_t,uint32_t>> semaphores;
    mutable uint64_t nextEvent=0x760000000000ull;
    mutable uint32_t randomState=1;
    mutable uint32_t localeMode=2; // single guest thread, global locale by default
    mutable uint32_t appType=0,fileMode=0x4000,newMode=0;
    mutable uint32_t lastError=0;
    bool cooperativeWaits=false;
    mutable bool waitPending=false;
    mutable WaitRequest pendingWait{};

    ThreadCreator threadCreator;
    ThreadExitQuery threadExitQuery;
    std::function<bool(uint64_t)> threadFinishedQuery;

    mutable std::unordered_map<uint64_t,uint64_t> threadHandles;
    mutable uint64_t nextThreadHandle=0x770000000000ULL;
    mutable uint64_t activeThread=1;
    mutable uint64_t activeTeb=ScarlettRuntime64::Teb;

    struct ThreadLocal {
        uint32_t error=0;
        std::unordered_map<uint32_t,uint64_t> values,fls;
    };

    mutable std::unordered_map<uint64_t,ThreadLocal> threadLocals;
    const std::chrono::steady_clock::time_point started=std::chrono::steady_clock::now();
    mutable std::unordered_map<uint64_t,uint64_t> virtualBlocks;
    mutable std::map<uint64_t,uint64_t> lifecycleBlocks;
    mutable std::unordered_map<uint32_t,uint64_t> tlsValues,flsSlots;
    const uint64_t pointerCookie=uint64_t(std::chrono::steady_clock::now().time_since_epoch().count()) ^ 0x9e3779b97f4a7c15ULL;

    
public:
    bool enableNativeVirtual() {
        if(!lifecycleBlocks.empty() ||
           !virtualBlocks.empty())
            return false;

        virtualNext=GuestMemory64::DirectVirtualBase;
        virtualLimit=GuestMemory64::DirectVirtualLimit;
        return true;
    }

private:
    uint64_t virtualLimit=0x600000000000ULL;
    mutable uint64_t virtualNext=0x510000000000ULL;

    
public:
    bool enableNativeHeap() {
        if(used || !blocks.empty() || !recycled.empty())
            return false;

        next=GuestMemory64::DirectHeapBase;
        heapLimit=GuestMemory64::DirectHeapLimit;
        return true;
    }

private:
    mutable uint64_t heapLimit=0x730000000000ull;
    mutable uint64_t next=0x720000000000ull, used=0;
    mutable std::unordered_map<uint64_t,std::pair<uint64_t,uint64_t>> blocks;
    mutable std::multimap<uint64_t,uint64_t> recycled;
    uint64_t allocate(GuestMemory64& m,uint64_t size) const {
        if(size>64*1024*1024)return 0;
        uint64_t span=(std::max<uint64_t>(size,1)+4095)&~4095ull;
        if(span>128*1024*1024-used)return 0;
        auto reuse=recycled.find(span);
        if(reuse!=recycled.end()){
            auto a=reuse->second;recycled.erase(reuse);
            if(m.map(a,span,GuestMemory64::Read|GuestMemory64::Write)==GuestMemory64::Fault::none){used+=span;blocks.emplace(a,std::pair{size,span});return a;}
        }
        if(next>heapLimit-span)return 0;
        auto a=next;if(m.map(a,span,GuestMemory64::Read|GuestMemory64::Write)!=GuestMemory64::Fault::none)return 0;
        next+=span;used+=span;blocks.emplace(a,std::pair{size,span});return a;
    }
    bool release(GuestMemory64& m,uint64_t a) const {auto i=blocks.find(a);if(i==blocks.end())return false;auto span=i->second.second;if(m.unmap(a,span)!=GuestMemory64::Fault::none)return false;used-=span;blocks.erase(i);if(recycled.size()<32768)recycled.emplace(span,a);return true;}

    // ---- V82 services -------------------------------------------------
    // Names occupy consecutive 16-byte stubs from StubBase+0x1800. Entries
    // from v82XboxFirst onward are bound only in the experimental Xbox profile.
    static constexpr std::array<const char*,38> v82Names{
        "Sleep","CreateMutexA","ReleaseMutex","GlobalMemoryStatusEx",
        "MultiByteToWideChar","WideCharToMultiByte","GetModuleFileNameA","GetModuleFileNameW",
        "CoCreateGuid","CoInitializeEx","CoUninitialize","CoCreateInstance","CoTaskMemFree",
        "PropVariantClear","GetStartupInfoW","GetUserDefaultLocaleName","GetUserDefaultGeoName",
        "LocaleNameToLCID","RegisterAppStateChangeNotification","UnregisterAppStateChangeNotification",
        "RegisterAppConstrainedChangeNotification","UnregisterAppConstrainedChangeNotification",
        "GetThreadGroupAffinity","SetThreadGroupAffinity","UnhandledExceptionFilter",
        "SetThreadPriority","GetThreadPriority","LoadLibraryW","LoadLibraryExA","LoadLibraryExW",
        "FreeLibrary","LocalFree","SetProcessPriorityBoost",
        "XMemAlloc","XMemFree","XMemAllocDefault","XMemFreeDefault","XMemIsToolsMemAvailable"};
    static constexpr unsigned v82XboxFirst=33;

    mutable uint64_t sleepHandle=0;
    mutable std::unordered_map<uint64_t,bool> mutexHandles;
    mutable std::unordered_map<uint64_t,int32_t> threadPriorities;
    mutable uint32_t comInitCount=0;
    mutable uint64_t guidState=0x9e3779b97f4a7c15ull;
    mutable uint64_t notifyToken=0x7a0000000000ull;

    static void putLE(std::vector<uint8_t>& out,uint64_t v,unsigned bytes){for(unsigned i=0;i<bytes;++i)out.push_back(uint8_t(v>>(8*i)));}

    bool readBytesZ(GuestMemory64& m,uint64_t a,bool wide,std::vector<uint32_t>& out,uint64_t limit) const {
        const unsigned unit=wide?2:1;
        for(uint64_t i=0;i<limit;++i){
            if(a>UINT64_MAX-i*unit-unit)return false;
            std::array<uint8_t,2>b{};
            if(m.read(a+i*unit,std::span<uint8_t>(b).first(unit))!=GuestMemory64::Fault::none)return false;
            uint32_t v=wide?uint32_t(b[0])|uint32_t(b[1])<<8:b[0];
            if(!v)return true;
            out.push_back(v);
        }
        return false;
    }

    // Decodes UTF-8. Invalid sequences either fail or become U+FFFD per byte.
    static bool decodeUtf8(const std::vector<uint8_t>& in,bool strict,std::vector<uint32_t>& cps){
        for(size_t i=0;i<in.size();){
            uint8_t c=in[i];uint32_t cp=0;unsigned len=0;
            if(c<0x80){cp=c;len=1;}
            else if(c>=0xc2&&c<=0xdf){cp=c&0x1f;len=2;}
            else if(c>=0xe0&&c<=0xef){cp=c&0x0f;len=3;}
            else if(c>=0xf0&&c<=0xf4){cp=c&0x07;len=4;}
            bool ok=len&&i+len<=in.size();
            for(unsigned k=1;ok&&k<len;++k){if((in[i+k]&0xc0)!=0x80)ok=false;else cp=(cp<<6)|(in[i+k]&0x3f);}
            if(ok&&len==3&&(cp<0x800||(cp>=0xd800&&cp<=0xdfff)))ok=false;
            if(ok&&len==4&&(cp<0x10000||cp>0x10ffff))ok=false;
            if(!ok){if(strict)return false;cps.push_back(0xfffd);++i;continue;}
            cps.push_back(cp);i+=len;
        }
        return true;
    }

    static std::string wideLower(const std::vector<uint32_t>& w){std::string s;for(auto c:w)s.push_back(c<128?char(c>='A'&&c<='Z'?c+32:c):'?');return s;}

    bool writeBlob(GuestMemory64& m,uint64_t a,const std::vector<uint8_t>& b) const {
        return b.empty()||m.write(a,b)==GuestMemory64::Fault::none;
    }

    bool dispatchV82(const std::string& n,GuestMemory64& memory,uint64_t rcx,uint64_t rdx,uint64_t r8,uint64_t r9,
                     uint64_t arg5,uint64_t arg6,uint64_t arg7,uint64_t& rax) const {
        using F=GuestMemory64::Fault;
        rax=0;
        auto fail=[&](uint32_t err,uint64_t value=0){lastError=err;rax=value;return true;};

        if(n=="Sleep"){
            const uint32_t ms=uint32_t(rcx);
            if(!ms)return true;
            if(!cooperativeWaits || waitPending)return false; // never fabricate elapsed time
            if(!sleepHandle || !events.contains(sleepHandle)){
                if(nextEvent==UINT64_MAX)return false;
                sleepHandle=nextEvent++;events.emplace(sleepHandle,Event{true,false});
            }
            pendingWait={sleepHandle,ms};waitPending=true;return true;
        }
        if(n=="CreateMutexA"){
            if(rcx||r8)return false; // security attributes and named mutexes unsupported
            if(events.size()+semaphores.size()>=65536 || nextEvent==UINT64_MAX)return fail(8);
            rax=nextEvent++;events.emplace(rax,Event{false,uint32_t(rdx)==0});mutexHandles[rax]=true;return true;
        }
        if(n=="ReleaseMutex"){
            auto m=mutexHandles.find(rcx);auto e=events.find(rcx);
            if(m==mutexHandles.end()||e==events.end())return fail(6);
            if(e->second.signaled)return fail(288); // ERROR_NOT_OWNER: not currently held
            e->second.signaled=true;rax=1;return true;
        }
        if(n=="GlobalMemoryStatusEx"){
            uint64_t len=0;
            if(!ScarlettRuntime64::readValue(memory,rcx,4,len))return false;
            if(len!=64)return fail(87);
            constexpr uint64_t total=12ull<<30,reserved=2ull<<30,virt=0x00007fffffff0000ull;
            const uint64_t inUse=std::min(total,reserved+used);
            std::vector<uint8_t> b;
            putLE(b,64,4);putLE(b,inUse*100/total,4);putLE(b,total,8);putLE(b,total-inUse,8);
            putLE(b,total,8);putLE(b,total-inUse,8);putLE(b,virt,8);putLE(b,virt-used,8);putLE(b,0,8);
            if(!writeBlob(memory,rcx,b))return false;
            rax=1;return true;
        }
        if(n=="MultiByteToWideChar"){
            const uint32_t cp=uint32_t(rcx),flags=uint32_t(rdx);const int32_t srcLen=int32_t(r9);const uint32_t dstCap=uint32_t(arg6);
            const bool utf8=cp==0||cp==1||cp==3||cp==65001,latin=cp==28591||cp==20127;
            if(!utf8&&!latin)return fail(87);
            if(flags&~0xfu)return fail(1004);
            if(!r8||srcLen==0||srcLen<-1)return fail(87);
            std::vector<uint8_t> raw;
            if(srcLen==-1){
                for(uint64_t i=0;;++i){
                    if(i>16*1024*1024||r8>UINT64_MAX-i)return false;
                    std::array<uint8_t,1>c{};if(memory.read(r8+i,c)!=F::none)return false;
                    raw.push_back(c[0]);if(!c[0])break;
                }
            }else{
                if(uint32_t(srcLen)>16*1024*1024)return false;
                raw.resize(uint32_t(srcLen));if(memory.read(r8,raw)!=F::none)return false;
            }
            std::vector<uint32_t> cps;
            if(utf8){if(!decodeUtf8(raw,flags&8,cps))return fail(1113);}
            else for(auto c:raw)cps.push_back(cp==20127&&c>0x7f?0xfffd:c);
            std::vector<uint8_t> out;uint32_t units=0;
            for(auto c:cps){
                if(c>=0x10000){c-=0x10000;putLE(out,0xd800+(c>>10),2);putLE(out,0xdc00+(c&0x3ff),2);units+=2;}
                else{putLE(out,c,2);++units;}
            }
            if(!dstCap){rax=units;return true;}
            if(dstCap<units)return fail(122);
            if(arg5==0||arg5==UINT64_MAX||!writeBlob(memory,arg5,out))return false;
            rax=units;return true;
        }
        if(n=="WideCharToMultiByte"){
            const uint32_t cp=uint32_t(rcx),flags=uint32_t(rdx);const int32_t srcLen=int32_t(r9);const uint32_t dstCap=uint32_t(arg6);
            const bool utf8=cp==0||cp==1||cp==3||cp==65001,latin=cp==28591||cp==20127;
            if(!utf8&&!latin)return fail(87);
            if(cp==65001&&((flags&~0x80u)||arg7))return fail(87);
            if(!r8||srcLen==0||srcLen<-1)return fail(87);
            std::vector<uint32_t> w;
            if(srcLen==-1){
                if(!readBytesZ(memory,r8,true,w,16*1024*1024))return false;
                w.push_back(0);
            }else{
                if(uint32_t(srcLen)>16*1024*1024)return false;
                std::vector<uint8_t> raw(uint64_t(uint32_t(srcLen))*2);
                if(memory.read(r8,raw)!=F::none)return false;
                for(size_t i=0;i<raw.size();i+=2)w.push_back(raw[i]|raw[i+1]<<8);
            }
            uint8_t defaultChar='?';
            if(arg7){std::array<uint8_t,1>d{};if(memory.read(arg7,d)!=F::none)return false;defaultChar=d[0];}
            std::vector<uint8_t> out;
            for(size_t i=0;i<w.size();++i){
                uint32_t c=w[i];
                if(c>=0xd800&&c<=0xdbff&&i+1<w.size()&&w[i+1]>=0xdc00&&w[i+1]<=0xdfff){c=0x10000+((c-0xd800)<<10)+(w[i+1]-0xdc00);++i;}
                else if(c>=0xd800&&c<=0xdfff){if(flags&0x80)return fail(1113);c=0xfffd;}
                if(latin){out.push_back(c<=(cp==20127?0x7fu:0xffu)?uint8_t(c):defaultChar);continue;}
                if(c<0x80)out.push_back(uint8_t(c));
                else if(c<0x800){out.push_back(uint8_t(0xc0|c>>6));out.push_back(uint8_t(0x80|(c&0x3f)));}
                else if(c<0x10000){out.push_back(uint8_t(0xe0|c>>12));out.push_back(uint8_t(0x80|((c>>6)&0x3f)));out.push_back(uint8_t(0x80|(c&0x3f)));}
                else{out.push_back(uint8_t(0xf0|c>>18));out.push_back(uint8_t(0x80|((c>>12)&0x3f)));out.push_back(uint8_t(0x80|((c>>6)&0x3f)));out.push_back(uint8_t(0x80|(c&0x3f)));}
            }
            if(!dstCap){rax=out.size();return true;}
            if(dstCap<out.size())return fail(122);
            if(arg5==0||arg5==UINT64_MAX||!writeBlob(memory,arg5,out))return false;
            rax=out.size();return true;
        }
        if(n=="GetModuleFileNameA"||n=="GetModuleFileNameW"){
            std::string path;
            if(!rcx||(imageBase&&rcx==imageBase))path="C:\\guest.exe";
            else{
                bool found=false;
                for(const auto& [key,handle]:modules)if(handle==rcx){path="C:\\Windows\\System32\\"+key;found=true;break;}
                if(!found)return fail(6);
            }
            const bool wide=n.back()=='W';const uint32_t cap=uint32_t(r8);
            if(!cap)return fail(122);
            const uint32_t keep=uint32_t(std::min<uint64_t>(path.size(),cap-1));
            std::vector<uint8_t> out;
            for(uint32_t i=0;i<keep;++i)putLE(out,uint8_t(path[i]),wide?2:1);
            putLE(out,0,wide?2:1);
            if(!rdx||!writeBlob(memory,rdx,out))return false;
            if(keep<path.size())return fail(122,cap);
            rax=keep;return true;
        }
        if(n=="CoCreateGuid"){
            std::vector<uint8_t> b;
            for(int k=0;k<2;++k){guidState^=guidState<<13;guidState^=guidState>>7;guidState^=guidState<<17;putLE(b,guidState,8);}
            b[7]=uint8_t((b[7]&0x0f)|0x40);b[8]=uint8_t((b[8]&0x3f)|0x80);
            if(!rcx||!writeBlob(memory,rcx,b))return false;
            return true;
        }
        if(n=="CoInitializeEx"){
            if(rcx){rax=0x80070057u;return true;}
            rax=comInitCount++?1:0;return true;
        }
        if(n=="CoUninitialize"){if(comInitCount)--comInitCount;return true;}
        if(n=="CoCreateInstance"){
            if(!arg5||arg5==UINT64_MAX){rax=0x80004003u;return true;}
            std::array<uint8_t,8>z{};if(memory.write(arg5,z)!=F::none)return false;
            rax=0x80040154u;return true; // REGDB_E_CLASSNOTREG: no COM classes are registered
        }
        if(n=="CoTaskMemFree"){
            if(!rcx)return true;
            return release(memory,rcx);
        }
        if(n=="PropVariantClear"){
            if(!rcx){rax=0x80070057u;return true;}
            std::vector<uint8_t> z(24);return memory.write(rcx,z)==F::none;
        }
        if(n=="GetStartupInfoW"){
            std::vector<uint8_t> b(104);b[0]=104;
            return rcx&&memory.write(rcx,b)==F::none;
        }
        if(n=="GetUserDefaultLocaleName"||n=="GetUserDefaultGeoName"){
            const bool geo=n=="GetUserDefaultGeoName";
            const std::string text=geo?"US":"en-US";const uint32_t need=uint32_t(text.size()+1);
            if(uint32_t(rdx)<need)return fail(122);
            std::vector<uint8_t> b;for(char c:text)putLE(b,uint8_t(c),2);putLE(b,0,2);
            if(!rcx||!writeBlob(memory,rcx,b))return false;
            rax=need;return true;
        }
        if(n=="LocaleNameToLCID"){
            if(!rcx){rax=0x0409;return true;}
            std::vector<uint32_t> w;if(!readBytesZ(memory,rcx,true,w,86))return false;
            const std::string name=wideLower(w);
            if(name.empty())rax=0x007f;
            else if(name=="en-us")rax=0x0409;
            else if(name=="en-gb")rax=0x0809;
            else if(name=="en")rax=0x0009;
            else return fail(87);
            return true;
        }
        if(n=="RegisterAppStateChangeNotification"||n=="RegisterAppConstrainedChangeNotification"){
            if(!r8){rax=87;return true;}
            std::vector<uint8_t> b;putLE(b,notifyToken+=16,8);
            if(memory.write(r8,b)!=F::none)return false;
            return true; // ERROR_SUCCESS; the app is never suspended or constrained, so callbacks never fire
        }
        if(n=="UnregisterAppStateChangeNotification"||n=="UnregisterAppConstrainedChangeNotification")return true;
        if(n=="GetThreadGroupAffinity"){
            std::vector<uint8_t> b;putLE(b,0xff,8);putLE(b,0,8);
            if(!rdx||!writeBlob(memory,rdx,b))return false;
            rax=1;return true;
        }
        if(n=="SetThreadGroupAffinity"){
            std::array<uint8_t,16> in{};
            if(!rdx||memory.read(rdx,in)!=F::none)return false;
            uint64_t mask=0;for(unsigned i=0;i<8;++i)mask|=uint64_t(in[i])<<(8*i);
            if(!mask||(mask&~0xffull)||in[8]||in[9])return fail(87);
            if(r8){std::vector<uint8_t> b;putLE(b,0xff,8);putLE(b,0,8);if(memory.write(r8,b)!=F::none)return false;}
            rax=1;return true;
        }
        if(n=="UnhandledExceptionFilter"){rax=0;return true;} // EXCEPTION_CONTINUE_SEARCH
        if(n=="SetThreadPriority"||n=="GetThreadPriority"){
            const bool get=n[0]=='G';
            if(rcx!=UINT64_MAX-1&&!threadHandles.contains(rcx))return fail(6,get?0x7fffffffu:0);
            if(get){auto p=threadPriorities.find(rcx);rax=uint32_t(p==threadPriorities.end()?0:p->second);return true;}
            const int32_t v=int32_t(rdx);
            if(v!=-15&&v!=-2&&v!=-1&&v!=0&&v!=1&&v!=2&&v!=15&&v!=0x10000&&v!=0x20000)return fail(87);
            threadPriorities[rcx]=v;rax=1;return true; // recorded only; scheduler is cooperative
        }
        if(n=="LoadLibraryW"||n=="LoadLibraryExA"||n=="LoadLibraryExW"){
            const bool wide=n.back()=='W';
            if(!rcx)return fail(87);
            std::vector<uint32_t> w;if(!readBytesZ(memory,rcx,wide,w,1024))return false;
            std::string key=wideLower(w);
            auto slash=key.find_last_of("\\/");if(slash!=std::string::npos)key=key.substr(slash+1);
            if(key.find('.')==std::string::npos)key+=".dll";
            auto m=modules.find(key);
            if(std::getenv("ALIEN_TRACE")) std::fprintf(stderr,"LOAD module=%s flags=%llx result=%llx\n",key.c_str(),(unsigned long long)(n=="LoadLibraryW"?0:r8),(unsigned long long)(m==modules.end()?0:m->second));
            if(m==modules.end()){if(dynamicLoader && (rax=dynamicLoader(key)))return true;return fail(126);}
            rax=m->second;return true;
        }
        if(n=="FreeLibrary"){
            for(const auto& [key,handle]:modules)if(handle==rcx){rax=1;return true;}
            return fail(6);
        }
        if(n=="LocalFree"){
            if(!rcx)return true;
            if(!release(memory,rcx))return fail(6,rcx); // failure returns the handle
            return true;
        }
        if(n=="SetProcessPriorityBoost"){rax=1;return true;} // accepted; no effect on the cooperative scheduler
        if(n=="XMemAlloc"||n=="XMemAllocDefault"){
            rax=allocate(memory,rcx); // attributes (rdx) ignored; blocks are 4 KiB aligned
            return true;
        }
        if(n=="XMemFree"||n=="XMemFreeDefault"){
            if(!rcx)return true;
            return release(memory,rcx);
        }
        if(n=="XMemIsToolsMemAvailable"){rax=0;return true;}
        (void)r9;
        return false;
    }
    GraphicsDispatch graphicsDispatch;
    std::unordered_map<uint64_t,std::string> imports;
};

}
