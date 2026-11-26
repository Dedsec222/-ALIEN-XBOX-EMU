#pragma once
#include "scarlett_runtime64.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdint>
#include <cfenv>

namespace genesis {

inline bool guestCrtFormat(
    GuestMemory64& memory,
    uint64_t options,
    uint64_t buffer,
    uint64_t capacity,
    uint64_t format,
    uint64_t locale,
    uint64_t args,
    uint64_t& rax, bool secure=false, uint64_t maxCount=UINT64_MAX, bool counted=false, bool wide=false)
{
    using F=GuestMemory64::Fault;
    constexpr size_t LIMIT=1048576;

    // UCRT: 0x04 legacy wide specifiers, 0x20 standard rounding.
    if(locale || capacity>LIMIT || (options&~uint64_t(0x27)))
        return false;

    auto readString=[&](uint64_t addr,
                        std::string& out,
                        size_t limit,
                        bool bounded=false){
        for(size_t i=0;i<limit;++i){
            uint8_t b[2]{}; size_t unit=wide?2:1;
            if(i>(UINT64_MAX-addr)/unit || memory.read(addr+i*unit,std::span<uint8_t>(b,unit))!=F::none)return false;
            if(!b[0]&&!b[1])return true;
            if(wide && (b[1] || b[0]>127))return false;
            out.push_back(char(b[0]));
        }
        return bounded;
    };

    auto next=[&](uint64_t& v){
        if(args>UINT64_MAX-8 ||
           !ScarlettRuntime64::readValue(
               memory,args,8,v))
            return false;
        args+=8;
        return true;
    };

    std::string fmt,out;
    if(!readString(format,fmt,65536))
        return false;

    if(std::getenv("ALIEN_TRACE"))
        std::fprintf(stderr,
            "CRT FORMAT: %s\n",fmt.c_str());

    for(size_t i=0;i<fmt.size();++i){
        if(fmt[i]!='%'){
            out+=fmt[i];
            continue;
        }

        if(++i>=fmt.size())return false;
        if(fmt[i]=='%'){
            out+='%';
            continue;
        }

        std::string spec="%";

        while(i<fmt.size() &&
              std::strchr("-+ #0",fmt[i]))
            spec+=fmt[i++];

        auto number=[&](int& value){
            value=0;
            while(i<fmt.size() &&
                  fmt[i]>='0' && fmt[i]<='9'){
                value=value*10+fmt[i++]-'0';
                if(value>65536)return false;
            }
            return true;
        };

        int width=0,precision=-1;
        uint64_t v=0;

        if(i<fmt.size() && fmt[i]=='*'){
            if(!next(v))return false;
            int64_t w=int32_t(v);
            if(w<-65536 || w>65536)return false;
            if(w<0){spec+='-';w=-w;}
            width=int(w);
            ++i;
        }else if(!number(width))return false;

        if(width)spec+=std::to_string(width);

        if(i<fmt.size() && fmt[i]=='.'){
            ++i;
            if(i<fmt.size() && fmt[i]=='*'){
                if(!next(v))return false;
                precision=int32_t(v);
                ++i;
            }else if(!number(precision))return false;

            if(precision>65536)return false;
            if(precision>=0)
                spec+="."+std::to_string(precision);
        }

        std::string len;
        if(fmt.compare(i,3,"I64")==0 ||
           fmt.compare(i,3,"I32")==0){
            len=fmt.substr(i,3);i+=3;
        }else if(fmt.compare(i,2,"ll")==0 ||
                 fmt.compare(i,2,"hh")==0){
            len=fmt.substr(i,2);i+=2;
        }else if(i<fmt.size() &&
                 std::strchr("hljztLIw",fmt[i])){
            len+=fmt[i++];
        }

        if(i>=fmt.size())return false;
        char c=fmt[i];

        if(c=='n')return false;
        if(!next(v))return false;

        auto emit=[&](auto value){
            int n=std::snprintf(
                nullptr,0,spec.c_str(),value);
            if(n<0 || size_t(n)>LIMIT ||
               out.size()+size_t(n)>LIMIT)
                return false;

            std::vector<char> tmp(size_t(n)+1);
            if(std::snprintf(tmp.data(),tmp.size(),
                spec.c_str(),value)!=n)
                return false;

            out.append(tmp.data(),size_t(n));
            return true;
        };

        bool wide64=(len=="ll" || len=="I64" ||
                     len=="z" || len=="t" ||
                     len=="j" || len=="I");

        if(c=='d' || c=='i'){
            int64_t x=wide64?int64_t(v):int32_t(v);
            if(len=="h")x=int16_t(v);
            if(len=="hh")x=int8_t(v);
            spec+="ll";spec+=c;
            if(!emit((long long)x))return false;

        }else if(std::strchr("uxXo",c)){
            uint64_t x=wide64?v:uint32_t(v);
            if(len=="h")x=uint16_t(v);
            if(len=="hh")x=uint8_t(v);
            spec+="ll";spec+=c;
            if(!emit((unsigned long long)x))
                return false;

        }else if(c=='s'){
            if(!len.empty() && len!=(wide?"l":"h"))
                return false;
            std::string str;
            if(!v)str="(null)";
            else if(!readString(v,str,
                precision>=0?size_t(precision):LIMIT,
                precision>=0))
                return false;
            spec+='s';
            if(!emit(str.c_str()))return false;

        }else if(c=='c'){
            if(!len.empty() && len!=(wide?"l":"h"))
                return false;
            spec+='c';
            if(!emit(int(uint8_t(v))))return false;

        }else if(c=='p'){
            char ptr[17]{};
            std::snprintf(ptr,sizeof(ptr),
                "%016llX",(unsigned long long)v);
            spec+='s';
            if(!emit(ptr))return false;

        }else if(std::strchr("fFeEgGaA",c)){
            // Host printf uses the current rounding mode; legacy rounding is not emulated.
            if((options&0x20) && std::fegetround()!=FE_TONEAREST) return false;
            double d;
            std::memcpy(&d,&v,8);
            spec+=c;
            if(!emit(d))return false;

        }else{
            std::fprintf(stderr,
                "Unsupported CRT format: %c\n",c);
            return false;
        }

        if(out.size()>LIMIT)return false;
    }

    const bool standard=(options&2)!=0;

    if(secure && (!capacity || !buffer)) {rax=UINT32_MAX;return true;}
    if(secure && (out.size()>=capacity || (counted && out.size()>maxCount))){
        if(counted && (maxCount==UINT64_MAX || maxCount<capacity)){
            out.resize(std::min<size_t>(out.size(),std::min<uint64_t>(capacity-1,maxCount)));
            rax=UINT32_MAX;
        }else{out.clear();rax=UINT32_MAX;}
        std::vector<uint8_t> bytes;for(unsigned char c:out){bytes.push_back(c);if(wide)bytes.push_back(0);}bytes.push_back(0);if(wide)bytes.push_back(0);
        return memory.write(buffer,bytes)==F::none;
    }
    if(capacity && buffer){
        size_t n=std::min(
            out.size(),size_t(capacity-1));

        std::vector<uint8_t> bytes;
        for(size_t j=0;j<n;++j){bytes.push_back(uint8_t(out[j]));if(wide)bytes.push_back(0);}
        bytes.push_back(0);if(wide)bytes.push_back(0);

        if(memory.write(buffer,bytes)!=F::none)
            return false;
    }else if(capacity){
        return false;
    }

    rax=(!standard && out.size()>=capacity)
        ? UINT32_MAX
        : uint32_t(out.size());

    return true;
}

}
