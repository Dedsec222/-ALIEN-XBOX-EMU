#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <map>
#include <span>
#include <vector>

namespace genesis {

enum class GpuResult {
    success,
    invalidHandle,
    invalidRange,
    invalidState,
    outOfMemory,
    queueFull,
    busy
};

class ScarlettGpu {
public:
    using Handle=uint64_t;

    static constexpr uint64_t MaxMemory=256ULL<<20;
    static constexpr uint64_t MaxBuffer=64ULL<<20;
    static constexpr uint64_t Alignment=65536;

    enum class Opcode {
        fill,
        copy
    };

    struct Command {
        Opcode op;
        Handle src=0;
        Handle dst=0;
        uint64_t srcOffset=0;
        uint64_t dstOffset=0;
        uint64_t size=0;
        uint32_t pattern=0;
    };

private:
    struct Resource {
        uint64_t address;
        std::vector<uint8_t> bytes;
        uint64_t references=0;
    };

    struct Submission {
        uint64_t fence;
        std::vector<Command> commands;
    };

    std::map<Handle,Resource> resources;
    std::deque<Submission> pending;
    std::vector<Command> recording;

    Handle nextHandle=1;
    uint64_t nextAddress=0x100000000ULL;
    uint64_t allocated=0;
    uint64_t submitted=0;
    uint64_t completed=0;
    bool active=false;

    bool validRange(
        Handle h,uint64_t offset,
        uint64_t size) const {

        auto it=resources.find(h);

        if(it==resources.end())
            return false;

        return offset<=it->second.bytes.size()
            && size<=it->second.bytes.size()-offset;
    }

public:
    uint64_t allocatedBytes() const {
        return allocated;
    }

    uint64_t completedFence() const {
        return completed;
    }

    uint64_t submittedFence() const {
        return submitted;
    }

    size_t resourceCount() const {
        return resources.size();
    }

    size_t pendingCount() const {
        return pending.size();
    }

    GpuResult createBuffer(
        uint64_t size,Handle& handle){

        handle=0;

        if(!size || size>MaxBuffer)
            return GpuResult::invalidRange;

        if(size>MaxMemory-allocated ||
           resources.size()>=4096)
            return GpuResult::outOfMemory;

        uint64_t aligned=
            (size+Alignment-1)&~(Alignment-1);

        if(nextAddress>UINT64_MAX-aligned ||
           nextHandle==UINT64_MAX)
            return GpuResult::outOfMemory;

        try {
            Resource resource{
                nextAddress,
                std::vector<uint8_t>(size),
                0
            };

            resources.emplace(
                nextHandle,std::move(resource));

        } catch(const std::bad_alloc&){
            return GpuResult::outOfMemory;
        }

        handle=nextHandle++;
        nextAddress+=aligned;
        allocated+=size;

        return GpuResult::success;
    }

    uint64_t gpuAddress(Handle h) const {
        auto it=resources.find(h);

        return it==resources.end()
            ?0:it->second.address;
    }

    GpuResult destroyBuffer(Handle h){
        auto it=resources.find(h);

        if(it==resources.end())
            return GpuResult::invalidHandle;

        if(it->second.references)
            return GpuResult::busy;

        allocated-=it->second.bytes.size();
        resources.erase(it);

        return GpuResult::success;
    }

    GpuResult upload(
        Handle h,uint64_t offset,
        std::span<const uint8_t> data){

        if(!validRange(h,offset,data.size()))
            return GpuResult::invalidRange;

        auto& r=resources.at(h);

        if(r.references)
            return GpuResult::busy;

        std::copy(
            data.begin(),data.end(),
            r.bytes.begin()+offset);

        return GpuResult::success;
    }

    GpuResult download(
        Handle h,uint64_t offset,
        std::span<uint8_t> data) const {

        if(!validRange(h,offset,data.size()))
            return GpuResult::invalidRange;

        const auto& r=resources.at(h);

        if(r.references)
            return GpuResult::busy;

        std::copy_n(
            r.bytes.begin()+offset,
            data.size(),data.begin());

        return GpuResult::success;
    }

    GpuResult begin(){
        if(active)
            return GpuResult::invalidState;

        recording.clear();
        active=true;

        return GpuResult::success;
    }

    GpuResult fill(
        Handle dst,uint64_t offset,
        uint64_t size,uint32_t pattern){

        if(!active)
            return GpuResult::invalidState;

        if(!size || (offset&3) || (size&3)
           || !validRange(dst,offset,size))
            return GpuResult::invalidRange;

        if(recording.size()>=65536)
            return GpuResult::queueFull;

        recording.push_back({
            Opcode::fill,0,dst,0,
            offset,size,pattern
        });

        ++resources.at(dst).references;

        return GpuResult::success;
    }

    GpuResult copy(
        Handle src,Handle dst,
        uint64_t srcOffset,
        uint64_t dstOffset,
        uint64_t size){

        if(!active)
            return GpuResult::invalidState;

        if(!size ||
           !validRange(src,srcOffset,size) ||
           !validRange(dst,dstOffset,size))
            return GpuResult::invalidRange;

        if(recording.size()>=65536)
            return GpuResult::queueFull;

        recording.push_back({
            Opcode::copy,src,dst,
            srcOffset,dstOffset,size,0
        });

        ++resources.at(src).references;
        ++resources.at(dst).references;

        return GpuResult::success;
    }

    GpuResult cancel(){
        if(!active)
            return GpuResult::invalidState;

        for(const auto& c:recording){
            --resources.at(c.dst).references;

            if(c.op==Opcode::copy)
                --resources.at(c.src).references;
        }

        recording.clear();
        active=false;

        return GpuResult::success;
    }

    GpuResult submit(uint64_t& fence){
        fence=0;

        if(!active)
            return GpuResult::invalidState;

        if(pending.size()>=256 ||
           submitted==UINT64_MAX)
            return GpuResult::queueFull;

        pending.emplace_back();
        pending.back().fence=++submitted;
        pending.back().commands.swap(recording);

        fence=submitted;
        active=false;

        return GpuResult::success;
    }

    bool processOne(){
        if(pending.empty())
            return false;

        auto& batch=pending.front();

        for(const auto& c:batch.commands){
            auto& dst=resources.at(c.dst);

            if(c.op==Opcode::fill){
                for(uint64_t i=0;i<c.size;++i)
                    dst.bytes[c.dstOffset+i]=
                        uint8_t(c.pattern>>
                            ((i&3)*8));

            }else{
                auto& src=resources.at(c.src);

                std::memmove(
                    dst.bytes.data()+c.dstOffset,
                    src.bytes.data()+c.srcOffset,
                    c.size);

                --src.references;
            }

            --dst.references;
        }

        completed=batch.fence;
        pending.pop_front();

        return true;
    }

    bool wait(uint64_t fence){
        if(fence>submitted)
            return false;

        while(completed<fence){
            if(!processOne())
                return false;
        }

        return true;
    }
};

}
