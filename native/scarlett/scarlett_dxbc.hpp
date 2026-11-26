#pragma once
#include <cstdint>
#include <span>
#include <vector>
#include <algorithm>

namespace genesis {

class DxbcContainer {
public:
    struct Chunk {
        uint32_t tag;
        uint32_t offset;
        uint32_t size;
    };

    static constexpr uint32_t fourcc(
        char a,char b,char c,char d){
        return uint32_t(uint8_t(a))
            |(uint32_t(uint8_t(b))<<8)
            |(uint32_t(uint8_t(c))<<16)
            |(uint32_t(uint8_t(d))<<24);
    }

private:
    std::vector<Chunk> chunks;

    static uint32_t read32(
        std::span<const uint8_t> data,
        size_t offset){
        uint32_t value=0;
        for(unsigned i=0;i<4;++i)
            value|=uint32_t(data[offset+i])<<(i*8);
        return value;
    }

public:
    bool parse(std::span<const uint8_t> data){
        chunks.clear();

        if(data.size()<32 ||
           data.size()>(64ULL<<20))
            return false;

        if(read32(data,0)!=fourcc('D','X','B','C'))
            return false;

        if(read32(data,20)!=1 ||
           read32(data,24)!=data.size())
            return false;

        const uint32_t count=read32(data,28);

        if(!count || count>4096 ||
           count>(data.size()-32)/4)
            return false;

        const size_t tableEnd=32+size_t(count)*4;

        std::vector<Chunk> parsed;

        for(uint32_t i=0;i<count;++i){
            uint32_t off=read32(data,32+i*4);

            if((off&3) || off<tableEnd ||
               off>data.size()-8)
                return false;

            uint32_t size=read32(data,off+4);

            if(size>data.size()-off-8)
                return false;

            parsed.push_back({
                read32(data,off),off+8,size
            });
        }

        auto sorted=parsed;

        std::sort(sorted.begin(),sorted.end(),
            [](const Chunk& a,const Chunk& b){
                return a.offset<b.offset;
            });

        for(size_t i=1;i<sorted.size();++i){
            const auto& prev=sorted[i-1];

            if(uint64_t(prev.offset)+prev.size
               >sorted[i].offset-8)
                return false;
        }

        chunks.swap(parsed);
        return true;
    }

    size_t chunkCount() const {
        return chunks.size();
    }

    std::vector<uint32_t> shader(
        std::span<const uint8_t> data) const {

        const Chunk* selected=nullptr;

        for(const auto& c:chunks){
            if(c.tag==fourcc('S','H','D','R') ||
               c.tag==fourcc('S','H','E','X')){
                if(selected)return {};
                selected=&c;
            }
        }

        if(!selected)return {};

        const auto& c=*selected;

        if(c.size<8 || (c.size&3) ||
           c.offset>data.size() ||
           c.size>data.size()-c.offset)
            return {};

        std::vector<uint32_t> words;

        for(uint32_t i=0;i<c.size;i+=4)
            words.push_back(
                read32(data,c.offset+i));

        if(words[1]!=words.size())
            return {};

        return words;
    }
};

}
