#pragma once
#include "scarlett_cpu64.hpp"
#include "scarlett_pe64.hpp"
#include "scarlett_runtime64.hpp"
#include "scarlett_scheduler64.hpp"

#if defined(ALIEN_ENABLE_VULKAN)
#include "scarlett_vulkan.hpp"
#include "scarlett_graphics_com.hpp"
#include "scarlett_gpu_bridge.hpp"
#endif
#include <sstream>
#include <filesystem>
#include "scarlett_link64.hpp"

namespace genesis {
inline std::string launchScarlett(std::span<const uint8_t> file, uint64_t budget,bool translate=false,uint64_t quantum=4096, const std::filesystem::path& dllDir={}) {
    GuestMemory64 memory;
    const auto image=loadScarlettPe(file,memory);
    if (!image.error.empty()) return image.error;
    constexpr uint64_t stack=0x700000000000ull, size=1ULL<<20, rsp=stack+size-40;
    constexpr uint64_t sentinel=ScarlettImports64::StubBase+0x200;
#if defined(ALIEN_ENABLE_VULKAN)
    ScarlettVulkan gpu;
    uint64_t graphicsInitAttempts=0;

    ScarlettGraphicsCom graphics([&](){
        ++graphicsInitAttempts;
        return gpu.initialize();
    });
#endif

    ScarlettImports64 imports;
    imports.setImageBase(image.imageBase);
    imports.setExceptionDirectory(image.imageSize,image.exceptionRva,image.exceptionSize);
    if(!imports.install(memory))
        return "Guest import initialization failed";

#if defined(ALIEN_ENABLE_VULKAN)
    if(!graphics.install(memory,imports))
        return "Guest graphics registration failed";

    ScarlettGpuBridge<ScarlettVulkan> gpuBridge(gpu);

    constexpr const char* diagnosticExports[]={
        "AlienGpuCreateBuffer",
        "AlienGpuDestroyBuffer",
        "AlienGpuUpload",
        "AlienGpuDownload",
        "AlienGpuSubmit",
        "AlienGpuFence",
        "AlienGpuDrawTriangles"
    };

    for(unsigned i=0;i<7;++i){
        if(!imports.registerGraphicsStub(
            0x1500+i*16,diagnosticExports[i]))
            return "Diagnostic GPU registration failed";
    }

    imports.bindGraphicsDispatch(
        [&](uint64_t address,
            GuestMemory64& mem,
            const ScarlettImports64::AbiArguments& a,
            uint64_t& result)->bool{

        using F=GuestMemory64::Fault;

        const auto op=address-ScarlettImports64::StubBase;

        if(op<0x1500 || op>0x1560)
            return graphics.dispatch(address,mem,a,result);

        result=0;

        auto put=[&](uint64_t ptr,uint64_t value){
            std::array<uint8_t,8> bytes{};
            for(unsigned i=0;i<8;++i)
                bytes[i]=uint8_t(value>>(i*8));
            return mem.write(ptr,bytes)==F::none;
        };

        if(op==0x1500){
            if(mem.check(a[1],8,GuestMemory64::Write)
                !=F::none)return true;

            if(!put(a[1],0))return false;

            if(gpu.gpuName.empty())
                ++graphicsInitAttempts;

            if(!gpu.initialize())return true;

            uint64_t handle=0;
            if(!gpu.createBuffer(a[0],handle))
                return true;

            if(!put(a[1],handle)){
                gpu.destroyBuffer(handle);
                return false;
            }

            result=1;
            return true;
        }

        if(op==0x1510){
            result=gpu.destroyBuffer(a[0]);
            return true;
        }

        if(op==0x1520 || op==0x1530){
            constexpr uint64_t limit=16ULL<<20;

            if(!a[3] || a[3]>limit)
                return true;

            const auto permission=op==0x1520
                ?GuestMemory64::Read
                :GuestMemory64::Write;

            if(mem.check(a[2],a[3],permission)!=F::none)
                return true;

            try{
                std::vector<uint8_t> bytes(a[3]);

                if(op==0x1520){
                    if(mem.read(a[2],bytes)!=F::none)
                        return false;

                    result=gpu.upload(a[0],a[1],bytes);
                }else{
                    if(!gpu.download(a[0],a[1],bytes))
                        return true;

                    result=mem.write(a[2],bytes)==F::none;
                }
            }catch(const std::bad_alloc&){
                result=0;
            }

            return true;
        }

        if(op==0x1540){
            result=gpuBridge.submit(mem,a[0],a[1])
                ==GpuBridgeResult::success;
            return true;
        }


        // Diagnostic guest drawing ABI:
        // vertex handle, vertex offset, vertex count,
        // output handle, output offset, width, height,
        // DXBC guest address, DXBC byte count.
        if(op==0x1560){
            constexpr uint64_t MaxShader=1ULL<<20;

            if(!a[2] || a[2]>1048576 ||
               !a[5] || a[5]>2048 ||
               !a[6] || a[6]>2048 ||
               !a[8] || a[8]>MaxShader)
                return true;

            if(mem.check(a[7],a[8],GuestMemory64::Read)
               !=F::none)
                return true;

            try{
                std::vector<uint8_t> shader(a[8]);

                if(mem.read(a[7],shader)!=F::none)
                    return false;

                result=gpu.drawDxbcTriangles(
                    a[0],a[1],uint32_t(a[2]),
                    a[3],a[4],
                    uint32_t(a[5]),uint32_t(a[6]),
                    shader);

            }catch(const std::bad_alloc&){
                result=0;
            }

            return true;
        }

        if(op==0x1550){
            result=put(a[0],gpu.completedFence());
            return true;
        }

        return false;
    });

#endif

    std::map<std::string,std::filesystem::path> dllPaths;
    if(!dllDir.empty()){
        std::error_code ec;
        for(const auto& e:std::filesystem::directory_iterator(dllDir,ec)){
            if(!e.is_regular_file(ec))continue;
            auto name=e.path().filename().string();for(auto& c:name)if(c>='A'&&c<='Z')c+=32;
            if(name.ends_with(".dll")&&!dllPaths.emplace(name,e.path()).second)return "Ambiguous DLL name: "+name;
        }
        if(ec)return "DLL directory scan failed: "+ec.message();
    }
    ScarlettLink64 linker(memory,[&](const std::string& name){
        auto it=dllPaths.find(name);if(it==dllPaths.end())return std::vector<uint8_t>{};
        std::ifstream f(it->second,std::ios::binary);return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),{});
    },[&](const std::string& lib,const std::string& sym){return imports.registerImport(lib,sym);});
    linker.entrylessOnly=true;
    imports.bindDynamicLoader([&](const std::string& name)->uint64_t{
        if(!linker.link(name)){std::cerr<<"LIVE DLL rejected: "<<linker.error<<'\n';return 0;}
        for(const auto& [key,mod]:linker.modules)if(!imports.publishEntrylessModule(key,mod.pe.imageBase,mod.exports.addresses))return 0;
        return linker.modules.at(name).pe.imageBase;
    });
    if(!resolveScarlettImports(memory,image,imports))
        return "Guest PE import resolution failed";
    if (memory.map(stack,size,3)!=GuestMemory64::Fault::none ||
        !ScarlettRuntime64::put64(memory,rsp,sentinel) ||
        !ScarlettRuntime64{}.install(memory,image.imageBase,stack,size)) return "Guest stack or TLS initialization failed";
    Arm64Blocks blocks;
    ScarlettScheduler64 scheduler(memory,&imports);

    scheduler.setImageBase(image.imageBase);
    scheduler.setBackend(translate?&blocks:nullptr);

    const auto mainId=scheduler.adoptMain(
        image.entry,rsp,stack,size,sentinel);

    if(!mainId)
        return "Guest main thread initialization failed";

    imports.bindThreadCreator(
        [&](uint64_t entry,uint64_t arg,uint64_t size){
            return scheduler.create(
                entry,arg,size?size:1ULL<<20);
        });

    imports.bindThreadExitQuery(
        [&](uint64_t id,uint32_t& code){
            return scheduler.exitCode(id,code);
        });

    imports.bindThreadFinishedQuery(
        [&](uint64_t id){
            return scheduler.finished(id);
        });

    imports.enableCooperativeWaits(true);

    uint64_t retired=0;

    if(!quantum)return "Scheduler quantum must be positive";
    bool stalled=false;

    while(retired<budget){
        auto main=scheduler.get(mainId);

        if(!main ||
           main->status==ScarlettScheduler64::Status::finished ||
           main->status==ScarlettScheduler64::Status::faulted)
            break;

        auto executed=scheduler.run(
            std::min(quantum,budget-retired),quantum);

        retired+=executed;

        if(!executed){
            if(scheduler.advanceToNextTimeout())continue;
            stalled=scheduler.blocked()!=0;
            break;
        }
    }

    const auto main=scheduler.get(mainId);

    if(!main)return "Guest main thread lost";

    auto cpu=main->cpu;
    cpu.steps=retired;

    imports.enableCooperativeWaits(false);
    imports.bindThreadCreator({});
    imports.bindThreadExitQuery({});
    imports.bindThreadFinishedQuery({});
    std::ostringstream out;
    const char* reason="Instruction budget exhausted";
    switch (cpu.exit) {
        case Cpu64Exit::unsupported: reason="Unsupported guest instruction or service";break;
        case Cpu64Exit::memoryFault: reason="Guest memory fault";break;
        case Cpu64Exit::callbackIncomplete:
            reason="Nested guest callback incomplete";break;
        case Cpu64Exit::waiting: reason="Guest waiting";break;
        case Cpu64Exit::threadExit: reason="Guest thread exited";break;
        case Cpu64Exit::halt: reason="Guest halted";break;
        case Cpu64Exit::breakpoint: reason="Guest breakpoint";break;
        case Cpu64Exit::budget: if(cpu.rip==sentinel) reason="Guest entry returned";break;
    }
    if(stalled)reason="Guest stalled: all remaining threads await an external signal or each other";
    out<<reason<<"\nScarlett V81 scheduled runtime\nRIP 0x"<<std::hex<<cpu.rip<<"\nRAX 0x"<<cpu.gpr[0]
       <<"\nInstructions "<<std::dec<<cpu.steps<<"\nCommitted guest pages "<<memory.committedPages();

    out<<"\nGuest threads "<<scheduler.threadCount()
       <<"\nRunnable threads "<<scheduler.runnable()
       <<"\nBlocked threads "<<scheduler.blocked()
       <<"\nMain thread instructions "<<main->instructions
       <<"\nScheduler quantum "<<quantum;
    out<<"\nActive CRT callbacks "<<main->cpu.callbacks.size()<<"\nBytes at RIP";
    constexpr char hex[]="0123456789abcdef";
    for(unsigned i=0;i<15 && i<=UINT64_MAX-cpu.rip;++i){
        uint8_t byte=0;
        if(!memory.fetchByte(cpu.rip+i,byte))break;
        out<<' '<<hex[byte>>4]<<hex[byte&15];
    }
    if (translate) out<<"\nARM64 blocks compiled "<<blocks.translations<<", executed "<<blocks.calls<<", compile attempts "<<blocks.compileAttempts<<", negative cache hits "<<blocks.negativeHits;
#if defined(ALIEN_ENABLE_VULKAN)
    out<<"\nGraphics runtime registered"
       <<"\nGraphics initialization attempts "<<graphicsInitAttempts
       <<"\nGraphics device objects "<<graphics.objectCount()
       <<"\nVulkan resources "<<gpu.resourceCount()
       <<"\nVulkan allocated bytes "<<gpu.allocatedBytes()
       <<"\nVulkan completed fence "<<gpu.completedFence()
       <<"\nHardware GPU "
       <<(gpu.gpuName.empty()?"Not selected":gpu.gpuName);

    imports.bindGraphicsDispatch({});
#else
    out<<"\nVulkan runtime disabled in host build";
#endif

    return out.str();
}
}
