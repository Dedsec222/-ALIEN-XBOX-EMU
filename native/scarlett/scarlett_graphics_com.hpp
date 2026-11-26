#pragma once

#include "scarlett_imports64.hpp"
#include <array>
#include <map>
#include <cstdint>

namespace genesis {

class ScarlettGraphicsCom {
public:
    using ABI = ScarlettImports64;
    using Args = ABI::AbiArguments;
    using F = GuestMemory64::Fault;

    static constexpr uint64_t Create = 0x1400;
    static constexpr uint64_t Query = 0x1410;
    static constexpr uint64_t AddRef = 0x1420;
    static constexpr uint64_t Release = 0x1430;

    static constexpr uint32_t S_OK = 0;
    static constexpr uint32_t E_NOINTERFACE = 0x80004002;
    static constexpr uint32_t E_POINTER = 0x80004003;
    static constexpr uint32_t E_INVALIDARG = 0x80070057;
    static constexpr uint32_t E_OUTOFMEMORY = 0x8007000e;
    static constexpr uint32_t E_FAIL = 0x80004005;

    using Guid = std::array<uint8_t,16>;

    static constexpr Guid IUnknown{
        0,0,0,0,0,0,0,0,
        0xc0,0,0,0,0,0,0,0x46
    };

    static constexpr Guid Device{
        0xf1,0x19,0x98,0x18,
        0xb6,0x1d,0x57,0x4b,
        0xbe,0x54,0x18,0x21,
        0x33,0x9b,0x85,0xf7
    };

private:
    struct Object {
        uint32_t references=1;
    };

    std::map<uint64_t,Object> objects;

    static constexpr uint64_t Arena =
        0x780000000000ULL;

    static constexpr uint64_t Vtable = Arena;

    uint64_t next= Arena+4096;
    bool initialized=false;

    std::function<bool()> initializeBackend;

    static bool put64(
        GuestMemory64& memory,
        uint64_t address,uint64_t value){

        std::array<uint8_t,8> bytes{};

        for(unsigned i=0;i<8;++i)
            bytes[i]=uint8_t(value>>(8*i));

        return memory.write(address,bytes)==F::none;
    }

    static bool supported(const Guid& guid){
        return guid==IUnknown || guid==Device;
    }

public:
    explicit ScarlettGraphicsCom(
        std::function<bool()> backend)
        :initializeBackend(std::move(backend)){}

    ScarlettGraphicsCom(
        const ScarlettGraphicsCom&)=delete;

    ScarlettGraphicsCom& operator=(
        const ScarlettGraphicsCom&)=delete;

    size_t objectCount() const {
        return objects.size();
    }

    bool install(
        GuestMemory64& memory,ABI& imports){

        if(initialized)return false;

        if(memory.map(Vtable,4096,3)!=F::none)
            return false;

        if(!put64(memory,Vtable,
                  ABI::StubBase+Query) ||
           !put64(memory,Vtable+8,
                  ABI::StubBase+AddRef) ||
           !put64(memory,Vtable+16,
                  ABI::StubBase+Release))
            return false;

        uint8_t oldPermissions=0;
        if(memory.protect(Vtable,4096,1,oldPermissions)!=F::none)
            return false;

        if(!imports.registerGraphicsStub(
                Create,"D3D12CreateDevice") ||
           !imports.registerGraphicsStub(
                Query,"GraphicsQueryInterface") ||
           !imports.registerGraphicsStub(
                AddRef,"GraphicsAddRef") ||
           !imports.registerGraphicsStub(
                Release,"GraphicsRelease"))
            return false;

        imports.bindGraphicsDispatch(
            [this](uint64_t address,
                   GuestMemory64& mem,
                   const Args& args,
                   uint64_t& result){
                return dispatch(
                    address,mem,args,result);
            });

        initialized=true;
        return true;
    }

    bool dispatch(
        uint64_t address,
        GuestMemory64& memory,
        const Args& a,uint64_t& result){

        if(!initialized)return false;

        const auto op=address-ABI::StubBase;

        if(op==Create){
            Guid guid{};

            if(!a[2] ||
               memory.read(a[2],guid)!=F::none){
                result=E_POINTER;
                return true;
            }

            if(a[3] && !put64(memory,a[3],0)){
                result=E_POINTER;
                return true;
            }

            if(!supported(guid)){
                result=E_NOINTERFACE;
                return true;
            }

            // Default adapter, feature level 11.0.
            // Other capability profiles remain unsupported.
            if(a[0] || a[1]!=0xb000){
                result=E_INVALIDARG;
                return true;
            }

            if(!initializeBackend ||
               !initializeBackend()){
                result=E_FAIL;
                return true;
            }

            // Capability probe without object creation.
            if(!a[3]){
                result=1; // S_FALSE
                return true;
            }

            if(objects.size()>=256 ||
               next>=Arena+(4097ULL*4096)){
                result=E_OUTOFMEMORY;
                return true;
            }

            const auto object=next;

            if(memory.map(object,4096,3)!=F::none){
                result=E_OUTOFMEMORY;
                return true;
            }

            uint8_t oldPermissions=0;
            if(!put64(memory,object,Vtable) ||
               memory.protect(object,4096,1,oldPermissions)!=F::none){
                memory.unmap(object,4096);
                result=E_FAIL;
                return true;
            }

            try {
                objects.emplace(object,Object{});
            } catch(const std::bad_alloc&){
                memory.unmap(object,4096);
                result=E_OUTOFMEMORY;
                return true;
            }

            if(!put64(memory,a[3],object)){
                objects.erase(object);
                memory.unmap(object,4096);
                result=E_POINTER;
                return true;
            }

            next+=4096;
            result=S_OK;
            return true;
        }

        auto it=objects.find(a[0]);

        if(it==objects.end())return false;

        auto& refs=it->second.references;

        if(op==Query){
            Guid guid{};

            if(!a[2] || !put64(memory,a[2],0)){
                result=E_POINTER;
                return true;
            }

            if(!a[1] ||
               memory.read(a[1],guid)!=F::none){
                result=E_POINTER;
                return true;
            }

            if(!supported(guid)){
                result=E_NOINTERFACE;
                return true;
            }

            if(refs==UINT32_MAX){
                result=E_FAIL;
                return true;
            }

            if(!put64(memory,a[2],a[0])){
                result=E_POINTER;
                return true;
            }

            ++refs;
            result=S_OK;
            return true;
        }

        if(op==AddRef){
            if(refs==UINT32_MAX)return false;
            result=++refs;
            return true;
        }

        if(op==Release){
            if(refs==1){
                if(memory.unmap(a[0],4096)!=F::none)
                    return false;

                objects.erase(it);
                result=0;
            }else{
                result=--refs;
            }

            return true;
        }

        return false;
    }
};

}
