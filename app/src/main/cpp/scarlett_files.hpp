#pragma once
#include "guest_memory64.hpp"
#include <string>
#include <string_view>
#include <vector>

namespace genesis {
// Per-process binary scratch files. Guest paths never reach the host filesystem.
class GuestFiles {
    struct Stream {
        std::string path;
        size_t pos;
        bool readable, writable, append;
    };
    static constexpr size_t quota=8*1024*1024;
    std::unordered_map<std::string,std::vector<uint8_t>> files;
    std::unordered_map<uint64_t,Stream> streams;
    size_t used=0;
    uint64_t next=0x770000000000ULL;
    static bool string(GuestMemory64& mem,uint64_t ptr,std::string& out,size_t limit) {
        for (size_t i=0;i<=limit;++i) {
            uint8_t c;
            if (ptr>UINT64_MAX-i || mem.read(ptr+i,std::span(&c,1))!=GuestMemory64::Fault::none) return false;
            if (!c) return true;
            out.push_back(char(c));
        }
        return false;
    }
public:
    static constexpr std::array<std::string_view,11> names={"fopen","fclose","fflush","fread","fwrite","fseek","_fseeki64","ftell","rewind","fgetc","fputc"};
    bool call(std::string_view name,GuestMemory64& mem,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t& result,uint64_t errnoPtr) {
        using Fault=GuestMemory64::Fault;
        auto fail=[&](uint8_t error,uint64_t value) {
            result=value;
            return mem.write(errnoPtr,std::array<uint8_t,4>{error,0,0,0})==Fault::none;
        };
        if (name=="fopen") {
            std::string path,mode;
            if (!string(mem,a,path,255) || !string(mem,b,mode,5)) return false;
            if (path.empty() || path=="." || path==".." || path.find_first_of("/\\:")!=path.npos) return fail(13,0);
            // Text translation is unavailable. Require an explicit binary mode.
            if (mode!="rb" && mode!="wb" && mode!="ab" && mode!="rb+" && mode!="wb+" && mode!="ab+" &&
                mode!="r+b" && mode!="w+b" && mode!="a+b") return fail(22,0);
            if (mode[0]=='r' && !files.contains(path)) return fail(2,0);
            if (streams.size()>=64 || (!files.contains(path) && files.size()>=256)) return fail(24,0);
            auto& data=files[path];
            if (mode[0]=='w') { used-=data.size(); data.clear(); }
            const bool update=mode.find('+')!=mode.npos;
            result=next++;
            streams.emplace(result,Stream{path,0,update||mode[0]=='r',update||mode[0]!='r',mode[0]=='a'});
            return true;
        }
        if (name=="fflush" && !a) { result=0; return true; }
        const bool block=name=="fread" || name=="fwrite";
        const auto handle=block?d:name=="fputc"?b:a;
        auto it=streams.find(handle);
        if (it==streams.end()) return fail(9,block?0:UINT32_MAX);
        auto& stream=it->second;
        auto& data=files.at(stream.path);
        result=0;
        if (name=="fclose") { streams.erase(it); return true; }
        if (name=="fflush") return true;
        if (name=="ftell") { result=stream.pos; return true; }
        if (name=="rewind") { stream.pos=0; return true; }
        if (name=="fseek" || name=="_fseeki64") {
            if (c>2) return fail(22,UINT32_MAX);
            const int64_t offset=name=="fseek"?int32_t(b):int64_t(b);
            const int64_t base=c==0?0:c==1?stream.pos:data.size();
            if (offset < -base || offset>int64_t(quota)-base) return fail(22,UINT32_MAX);
            stream.pos=size_t(base+offset);
            return true;
        }
        const bool reading=name=="fread" || name=="fgetc";
        if (reading?!stream.readable:!stream.writable) return fail(9,block?0:UINT32_MAX);
        if (block && (!b || !c)) return true;
        if (block && c>UINT64_MAX/b) return fail(22,0);
        const auto count=block?b*c:1;
        if (reading) {
            const auto size=std::min<uint64_t>(count,data.size()-std::min(data.size(),stream.pos));
            if (!size) {result=block?0:UINT32_MAX;return true;}
            if (block && mem.write(a,std::span(data).subspan(stream.pos,size))!=Fault::none) return false;
            result=block?size/b:data[stream.pos];
            stream.pos+=size;
        } else {
            const size_t pos=stream.append?data.size():stream.pos;
            if (count>quota-pos) return fail(28,block?0:UINT32_MAX);
            const auto growth=std::max(data.size(),size_t(pos+count))-data.size();
            if (growth>quota-used) return fail(28,block?0:UINT32_MAX);
            if (block && mem.check(a,count,GuestMemory64::Read)!=Fault::none) return false;
            data.resize(data.size()+growth);
            used+=growth;
            if (block) {
                if (mem.read(a,std::span(data).subspan(pos,count))!=Fault::none) return false;
                result=c;
            } else { data[pos]=uint8_t(a); result=uint8_t(a); }
            stream.pos=pos+count;
        }
        return true;
    }
};
}
