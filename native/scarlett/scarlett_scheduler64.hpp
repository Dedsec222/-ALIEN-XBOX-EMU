#pragma once

#include "scarlett_cpu64.hpp"
#include <deque>
#include <chrono>
#include <map>
#include <algorithm>

namespace genesis {

class ScarlettScheduler64 {
public:
    enum class Status {
        ready, blocked, finished, faulted
    };

    struct Thread {
        uint64_t id=0;
        uint64_t stackBase=0;
        uint64_t stackSize=0;
        uint64_t gsBase=0;
        uint64_t fsBase=0;
        uint64_t tlsVector=0;
        uint64_t tlsData=0;
        uint64_t tlsSize=0;
        uint64_t instructions=0;
        uint64_t stopRip=0;
        bool ownsMemory=true;
        uint64_t waitHandle=0;
        uint32_t waitTimeout=0;
        std::chrono::steady_clock::time_point deadline{};
        Cpu64State cpu{};
        Status status=Status::ready;
    };

    explicit ScarlettScheduler64(
        GuestMemory64& memory,
        const ScarlettImports64* imports=nullptr)
        : mem(memory), api(imports) {}

    void setBackend(Arm64Blocks* blocks){
        backend=blocks;
    }

    void setImageBase(uint64_t base){
        imageBase=base;
    }

    uint64_t adoptMain(
        uint64_t entry,
        uint64_t rsp,
        uint64_t stackBase,
        uint64_t stackSize,
        uint64_t sentinel){

        if(!threads.empty() ||
           mem.check(entry,1,GuestMemory64::Execute)
               !=GuestMemory64::Fault::none)
            return 0;

        Thread t{};
        t.id=1;
        t.stackBase=stackBase;
        t.stackSize=stackSize;
        t.gsBase=ScarlettRuntime64::Teb;
        t.tlsVector=ScarlettRuntime64::Tls;
        t.stopRip=sentinel;
        t.ownsMemory=false;
        t.cpu.rip=entry;
        t.cpu.gpr[4]=rsp;

        threads.emplace(t.id,t);
        ready.push_back(t.id);

        nextId=2;
        return t.id;
    }

    uint64_t create(
        uint64_t entry,
        uint64_t parameter=0,
        uint64_t stackSize=1ULL<<20){

        using F=GuestMemory64::Fault;

        if(threads.size()>=64 ||
           stackSize<4096 ||
           stackSize>(8ULL<<20) ||
           mem.check(entry,1,GuestMemory64::Execute)
               !=F::none)
            return 0;

        stackSize=(stackSize+4095)&~4095ULL;

        uint64_t base=nextStack;
        uint64_t total=stackSize+12288;

        if(mem.map(base+4096,stackSize,3)!=F::none)
            return 0;

        if(mem.map(base+4096+stackSize,4096,3)!=F::none){
            mem.unmap(base+4096,stackSize);
            return 0;
        }

        if(mem.map(base+4096+stackSize+4096,4096,3)!=F::none){
            mem.unmap(base+4096,stackSize+4096);
            return 0;
        }

        if(!returnMapped){
            if(mem.map(ReturnAddress,4096,5)!=F::none){
                mem.unmap(base+4096,stackSize+8192);
                return 0;
            }
            returnMapped=true;
        }

        Thread t{};
        t.id=nextId++;
        t.stackBase=base+4096;
        t.stackSize=stackSize;
        t.gsBase=t.stackBase+stackSize;
        t.tlsVector=t.gsBase+4096;

        // Independent worker TEB.
        if(!ScarlettRuntime64::put64(mem,t.gsBase+0x08,
                                    t.stackBase+t.stackSize) ||
           !ScarlettRuntime64::put64(mem,t.gsBase+0x10,
                                    t.stackBase) ||
           !ScarlettRuntime64::put64(mem,t.gsBase+0x30,
                                    t.gsBase) ||
           !ScarlettRuntime64::put64(mem,t.gsBase+0x40,1000) ||
           !ScarlettRuntime64::put64(mem,t.gsBase+0x48,t.id) ||
           !ScarlettRuntime64::put64(mem,t.gsBase+0x58,
                                    t.tlsVector) ||
           !ScarlettRuntime64::put64(mem,t.gsBase+0x60,
                                    ScarlettRuntime64::Peb)){
            mem.unmap(t.stackBase,stackSize+8192);
            return 0;
        }

        t.stopRip=ReturnAddress;
        t.cpu.rip=entry;
        t.cpu.gpr[1]=parameter;

        uint64_t rsp=t.stackBase+stackSize-40;
        t.cpu.gpr[4]=rsp;

        std::array<uint8_t,8> ret{};
        for(unsigned i=0;i<8;++i)
            ret[i]=uint8_t(ReturnAddress>>(8*i));

        if(mem.write(rsp,ret)!=F::none){
            mem.unmap(t.stackBase,stackSize+8192);
            return 0;
        }

        if(imageBase){
            t.tlsData=nextTlsData;

            if(!ScarlettRuntime64::installStaticTls(
                    mem,imageBase,t.tlsVector,
                    t.tlsData,&t.tlsSize)){
                mem.unmap(t.stackBase,stackSize+8192);
                return 0;
            }

            nextTlsData+=0x1000000ULL;
        }

        nextStack+=total;
        threads.emplace(t.id,t);
        ready.push_back(t.id);
        return t.id;
    }

    uint64_t run(
        uint64_t budget,
        uint64_t quantum=4096){

        if(!quantum)return 0;
        uint64_t retired=0;

        while(retired<budget){
            wakeBlocked();
            if(ready.empty())break;
            uint64_t id=ready.front();
            ready.pop_front();

            auto& t=threads.at(id);

            if(t.status!=Status::ready)
                continue;

            if(api)
                api->selectThread(t.id,t.gsBase);

            auto result=executeGuest64(
                mem,
                t.cpu.rip,
                std::min(quantum,budget-retired),
                t.cpu.gpr[4],
                api,
                t.gsBase,
                t.fsBase,
                t.stopRip,
                0,
                &t.cpu,
                backend);

            retired+=result.steps;
            t.instructions+=result.steps;
            t.cpu=result;

            if(result.exit==Cpu64Exit::waiting){
                ScarlettImports64::WaitRequest request{};

                if(!api || !api->takeWaitRequest(request)){
                    t.status=Status::faulted;
                    continue;
                }

                t.waitHandle=request.handle;
                t.waitTimeout=request.timeout;

                t.deadline=std::chrono::steady_clock::now()+idleAdvance
                    +std::chrono::milliseconds(request.timeout);

                t.status=Status::blocked;
                continue;
            }

            if(result.exit==Cpu64Exit::threadExit ||
               (result.rip==t.stopRip &&
                result.exit==Cpu64Exit::budget)){
                t.status=Status::finished;
            }else if(result.exit!=Cpu64Exit::budget ||
                     !result.steps){
                t.status=Status::faulted;
            }else{
                ready.push_back(id);
            }
        }

        return retired;
    }

    void wakeBlocked(){
        if(!api)return;

        const auto now=std::chrono::steady_clock::now()+idleAdvance;

        for(auto& [id,t]:threads){
            if(t.status!=Status::blocked)continue;

            api->selectThread(id,t.gsBase);

            uint64_t result=UINT32_MAX;

            if(!api->pollThreadWait(t.waitHandle,result)){
                t.status=Status::faulted;
                continue;
            }

            if(result==258){
                if(t.waitTimeout==UINT32_MAX ||
                   now<t.deadline)
                    continue;
            }

            t.cpu.gpr[0]=result;
            t.cpu.exit=Cpu64Exit::budget;
            t.status=Status::ready;
            t.waitHandle=0;
            ready.push_back(id);
        }
    }

    // The caller drives the cooperative clock only while no guest is runnable.
    bool advanceToNextTimeout(){
        if(!ready.empty())return false;
        auto earliest=std::chrono::steady_clock::time_point::max();
        for(const auto& [id,t]:threads)
            if(t.status==Status::blocked && t.waitTimeout!=UINT32_MAX)
                earliest=std::min(earliest,t.deadline);
        if(earliest==std::chrono::steady_clock::time_point::max())return false;
        const auto now=std::chrono::steady_clock::now()+idleAdvance;
        if(earliest>now)idleAdvance+=earliest-now;
        wakeBlocked();
        return !ready.empty();
    }

    size_t blocked() const {
        size_t count=0;
        for(const auto& item:threads)
            if(item.second.status==Status::blocked)
                ++count;
        return count;
    }

    const Thread* get(uint64_t id) const {
        auto it=threads.find(id);
        return it==threads.end()?nullptr:&it->second;
    }

    bool finished(uint64_t id) const {
        auto t=get(id);
        return t && t->status==Status::finished;
    }

    bool exitCode(uint64_t id,uint32_t& code) const {
        auto t=get(id);
        if(!t || t->status==Status::faulted)
            return false;

        code=t->status==Status::finished
            ?uint32_t(t->cpu.gpr[0]):259;

        return true;
    }

    size_t threadCount() const {
        return threads.size();
    }

    size_t runnable() const {
        return ready.size();
    }

    bool reap(uint64_t id){
        auto it=threads.find(id);

        if(it==threads.end() ||
           (it->second.status==Status::ready ||
            it->second.status==Status::blocked))
            return false;

        auto& t=it->second;

        if(t.ownsMemory && mem.unmap(t.stackBase,t.stackSize+8192)
            !=GuestMemory64::Fault::none)
            return false;

        if(t.tlsSize &&
           mem.unmap(t.tlsData,t.tlsSize)
               !=GuestMemory64::Fault::none)
            return false;

        threads.erase(it);
        return true;
    }

private:
    std::chrono::steady_clock::duration idleAdvance{};
    GuestMemory64& mem;
    const ScarlettImports64* api;
    Arm64Blocks* backend=nullptr;

    static constexpr uint64_t ReturnAddress=
        0x680000000000ULL;

    uint64_t nextStack=0x690000000000ULL;
    uint64_t nextId=1;
    uint64_t imageBase=0;
    uint64_t nextTlsData=0x6a0000000000ULL;
    bool returnMapped=false;

    std::map<uint64_t,Thread> threads;
    std::deque<uint64_t> ready;
};

} // namespace genesis
