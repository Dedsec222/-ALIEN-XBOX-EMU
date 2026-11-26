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
        bool windows=false;
        unsigned share=0;
    };
    static constexpr size_t quota=8*1024*1024;
    std::unordered_map<std::string,std::vector<uint8_t>> files;
    std::unordered_map<uint64_t,Stream> streams;
    size_t used=0;
    uint64_t next=0x770000000000ULL;
    bool isOpen(const std::string& path) const {
        return std::any_of(streams.begin(),streams.end(),[&](const auto& item){return item.second.path==path;});
    }
    static bool string(GuestMemory64& mem,uint64_t ptr,std::string& out,size_t limit,bool wide=false) {
        for (size_t i=0;i<=limit;++i) {
            uint16_t c=0;
            const size_t width=wide?2:1;
            if (ptr>UINT64_MAX-i*width || mem.read(ptr+i*width,{reinterpret_cast<uint8_t*>(&c),width})!=GuestMemory64::Fault::none) return false;
            if (!c) return true;
            if(wide && c>127)return false;
            out.push_back(char(c));
        }
        return false;
    }
public:
    static constexpr std::array<std::string_view,12> winNames={
        "CreateFileW","ReadFile","WriteFile","GetFileSizeEx","SetFilePointerEx",
        "SetEndOfFile","FlushFileBuffers","DeleteFileW","GetFileAttributesW",
        "GetFileAttributesA","GetDiskFreeSpaceExW","MoveFileExW"
    };
    bool windowsHandle(uint64_t h) const {
        auto it=streams.find(h);
        return it!=streams.end() && it->second.windows;
    }
    bool winCall(std::string_view n,GuestMemory64& mem,uint64_t a,uint64_t b,uint64_t c,
                 uint64_t d,uint64_t arg5,uint64_t arg6,uint64_t arg7,uint64_t& ret,uint32_t& error) {
        using F=GuestMemory64::Fault;
        auto fail=[&](uint32_t code){
            error=code;
            ret=n=="CreateFileW"?UINT64_MAX:n.starts_with("GetFileAttributes")?UINT32_MAX:0;
            return true;
        };
        auto writable=[&](uint64_t ptr,unsigned size){return ptr && mem.check(ptr,size,GuestMemory64::Write)==F::none;};
        auto put=[&](uint64_t ptr,uint64_t value,unsigned size){
            return mem.write(ptr,{reinterpret_cast<const uint8_t*>(&value),size})==F::none;
        };
        auto valid=[](const std::string& path){
            return !path.empty() && path!="." && path!=".." && path.find_first_of("/\\:")==path.npos;
        };
        if(n=="GetDiskFreeSpaceExW"){
            std::string root;
            if(a && (!string(mem,a,root,255,true) || root!="."))return fail(3);
            if((b&&!writable(b,8)) || (c&&!writable(c,8)) || (d&&!writable(d,8)))return fail(998);
            ret=1;
            return (!b||put(b,quota-used,8)) && (!c||put(c,quota,8)) && (!d||put(d,quota-used,8));
        }
        if(n=="CreateFileW" || n=="DeleteFileW" || n.starts_with("GetFileAttributes") || n=="MoveFileExW"){
            std::string path;
            if(!string(mem,a,path,255,n!="GetFileAttributesA"))return fail(123);
            if(!valid(path))return fail(123);
            auto file=files.find(path);
            const bool exists=file!=files.end();
            if(n.starts_with("GetFileAttributes")){
                if(!exists)return fail(2);
                ret=0x80;return true;
            }
            if(n=="MoveFileExW" || n=="DeleteFileW"){
                if(!exists)return fail(2);
                if(isOpen(path))return fail(32);
                if(n=="DeleteFileW"){used-=file->second.size();files.erase(file);}
                else {
                    std::string dest;
                    if(c&~1u)return fail(50);
                    if(!string(mem,b,dest,255,true)||!valid(dest))return fail(123);
                    if(isOpen(dest))return fail(32);
                    if(dest==path){ret=1;return true;}
                    if(files.contains(dest)){
                        if(!(c&1))return fail(183);
                        used-=files.at(dest).size();
                        files.erase(dest);
                    }
                    auto node=files.extract(file);node.key()=dest;files.insert(std::move(node));
                }
                ret=1;return true;
            }
            // Synchronous flat files; reject unsupported security, flags and template handles.
            if(d || arg7 || (arg6&~0x80ull) || (b&~0xc0000000ull) || (c&~7ull) ||
               arg5<1 || arg5>5)return fail(50);
            const bool read=b&0x80000000,write=b&0x40000000;
            if(arg5==1 && exists)return fail(80);
            if((arg5==3 || arg5==5) && !exists)return fail(2);
            if(arg5==5 && !write)return fail(5);
            for(const auto& item:streams){
                const Stream& s=item.second;
                if(s.path!=path)continue;
                if(!s.windows || (read && !(s.share&1)) || (write && !(s.share&2)) ||
                   (s.readable && !(c&1)) || (s.writable && !(c&2)))return fail(32);
            }
            if(streams.size()>=64 || (!exists && files.size()>=256))return fail(4);
            auto& bytes=files[path];
            if(arg5==2 || arg5==5){used-=bytes.size();bytes.clear();}
            if(arg5==2 || arg5==4)error=exists?183:0;
            ret=next++;
            streams.emplace(ret,Stream{path,0,read,write,false,true,unsigned(c)});
            return true;
        }
        if(!windowsHandle(a))return fail(6);
        auto& stream=streams.at(a);
        auto& data=files.at(stream.path);
        ret=1;
        if(n=="CloseHandle"){streams.erase(a);return true;}
        if(n=="FlushFileBuffers")return stream.writable?true:fail(5);
        if(n=="GetFileSizeEx")return writable(b,8)?put(b,data.size(),8):fail(998);
        if(n=="SetFilePointerEx"){
            if(d>2)return fail(87);
            const int64_t base=d==0?0:d==1?stream.pos:data.size(),delta=int64_t(b);
            if(delta < -base)return fail(131);
            if(delta>int64_t(quota)-base)return fail(112);
            if(c && !writable(c,8))return fail(998);
            stream.pos=size_t(base+delta);
            return !c || put(c,stream.pos,8);
        }
        const bool read=n=="ReadFile";
        if(read?!stream.readable:!stream.writable)return fail(5);
        if(n=="SetEndOfFile"){
            if(stream.pos>data.size() && stream.pos-data.size()>quota-used)return fail(112);
            const auto old=data.size();
            data.resize(stream.pos);
            used=used-old+data.size();
            return true;
        }
        if(arg5)return fail(50); // OVERLAPPED requests need a completion mechanism
        if(!writable(d,4))return fail(998);
        if(!put(d,0,4))return false;
        const auto requested=uint32_t(c);
        if(!requested)return true;
        if(read){
            const auto count=std::min<size_t>(requested,data.size()-std::min(data.size(),stream.pos));
            if(count && mem.write(b,std::span(data).subspan(stream.pos,count))!=F::none)return fail(998);
            stream.pos+=count;return put(d,count,4);
        }
        if(requested>quota-stream.pos)return fail(112);
        const auto growth=std::max(data.size(),stream.pos+requested)-data.size();
        if(growth>quota-used)return fail(112);
        if(mem.check(b,requested,GuestMemory64::Read)!=F::none)return fail(998);
        data.resize(data.size()+growth);used+=growth;
        if(mem.read(b,std::span(data).subspan(stream.pos,requested))!=F::none)return false;
        stream.pos+=requested;return put(d,requested,4);
    }
    static constexpr std::array<std::string_view,11> names={"fopen","fclose","fflush","fread","fwrite","fseek","_fseeki64","ftell","rewind","fgetc","fputc"};
    bool call(std::string_view name,GuestMemory64& mem,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t& result,uint64_t errnoPtr) {
        using Fault=GuestMemory64::Fault;
        auto fail=[&](uint8_t error,uint64_t value) {
            result=value;
            return mem.write(errnoPtr,std::array<uint8_t,4>{error,0,0,0})==Fault::none;
        };
        if (name=="remove") {
            std::string path;
            if(!string(mem,a,path,255))return false;
            if(!files.contains(path))return fail(2,UINT32_MAX);
            if(isOpen(path))return fail(13,UINT32_MAX);
            used-=files.at(path).size();files.erase(path);result=0;return true;
        }
        if (name=="fopen" || name=="_wfopen") {
            std::string path,mode;
            if (!string(mem,a,path,255,name=="_wfopen") || !string(mem,b,mode,5,name=="_wfopen")) return false;
            if (path.empty() || path=="." || path==".." || path.find_first_of("/\\:")!=path.npos) return fail(13,0);
            // Text translation is unavailable. Require an explicit binary mode.
            if (mode!="rb" && mode!="wb" && mode!="ab" && mode!="rb+" && mode!="wb+" && mode!="ab+" &&
                mode!="r+b" && mode!="w+b" && mode!="a+b") return fail(22,0);
            for (const auto& pair:streams) if(pair.second.windows && pair.second.path==path)return fail(13,0);
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
        if (it==streams.end() || it->second.windows) return fail(9,block?0:UINT32_MAX);
        auto& stream=it->second;
        auto& data=files.at(stream.path);
        result=0;
        if (name=="fclose") { streams.erase(it); return true; }
        if (name=="fflush") return true;
        if(name=="fgetpos" || name=="fsetpos"){
            uint64_t pos=stream.pos;
            auto buf=std::span<uint8_t>(reinterpret_cast<uint8_t*>(&pos),8);
            if(name=="fgetpos")return mem.write(b,buf)==Fault::none;
            if(mem.read(b,buf)!=Fault::none)return false;
            if(pos>quota)return fail(22,UINT32_MAX);
            stream.pos=pos;return true;
        }
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
