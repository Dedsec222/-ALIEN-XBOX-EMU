#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <vector>
#include <initializer_list>

namespace genesis {

inline std::vector<uint32_t> translateArithmeticPixel(
    std::span<const uint32_t> code){

    using Words=std::vector<uint32_t>;
    using Vec=std::array<uint32_t,4>;

    if(code.size()<3 || code.size()>65536 ||
       (code[0]!=0x40 && code[0]!=0x50) ||
       code[1]!=code.size())
        return {};

    Words declarations,body,result;

    auto emit=[](Words& dst,uint32_t op,
                 std::initializer_list<uint32_t> args){
        dst.push_back(
            (uint32_t(args.size()+1)<<16)|op);
        dst.insert(dst.end(),args);
    };

    uint32_t next=10;

    auto id=[&](){return next++;};

    std::array<Vec,32> temps{};
    Vec output{};

    uint32_t tempCount=0;
    bool declaredTemps=false;
    bool declaredOutput=false;
    bool returned=false;
    bool started=false;

    auto constant=[&](uint32_t bits){
        uint32_t r=id();
        emit(declarations,43,{3,r,bits});
        return r;
    };

    auto binary=[&](uint32_t op,
                    uint32_t a,uint32_t b){
        uint32_t r=id();
        emit(body,op,{3,r,a,b});
        return r;
    };

    auto ext=[&](uint32_t op,
                 uint32_t a,uint32_t b){
        uint32_t r=id();
        emit(body,12,{3,r,9,op,a,b});
        return r;
    };

    size_t pc=2;

    while(pc<code.size()){

        uint32_t token=code[pc++];
        uint32_t op=token&0x7ff;
        uint32_t len=(token>>24)&0x7f;

        if(!len || len-1>code.size()-pc ||
           token!=(op|(len<<24)))
            return {};

        size_t end=pc+len-1;

        auto take=[&](uint32_t& v){
            if(pc>=end)return false;
            v=code[pc++];
            return true;
        };

        if(op==101){

            uint32_t operand,index;

            if(started || declaredOutput ||
               !take(operand) || !take(index) ||
               operand!=0x001020f2 || index!=0 ||
               pc!=end)
                return {};

            declaredOutput=true;
            continue;
        }

        if(op==104){

            if(started || declaredTemps ||
               !take(tempCount) ||
               !tempCount || tempCount>32 ||
               pc!=end)
                return {};

            declaredTemps=true;
            continue;
        }

        if(op==62){

            if(pc!=end || end!=code.size() ||
               !declaredOutput)
                return {};

            returned=true;
            break;
        }

        started=true;

        unsigned sources=0;

        switch(op){
            case 54:sources=1;break;
            case 0:
            case 51:
            case 52:
            case 56:sources=2;break;
            case 50:sources=3;break;
            default:return {};
        }

        uint32_t dst,index;

        if(!take(dst) || !take(index))
            return {};

        uint32_t type=(dst>>12)&0xff;
        uint32_t mask=(dst>>4)&15;

        if(!mask ||
           dst!=(0x00100002u|
                 (type<<12)|(mask<<4)))
            return {};

        Vec* target=nullptr;

        if(type==0 && index<tempCount)
            target=&temps[index];

        if(type==2 && index==0 && declaredOutput)
            target=&output;

        if(!target)return {};

        auto source=[&](Vec& v)->bool{

            uint32_t t;

            if(!take(t))return false;

            if(t==0x00004001){

                uint32_t bits;
                if(!take(bits))return false;

                v.fill(constant(bits));
                return true;
            }

            if(t==0x00004002){

                for(auto& lane:v){
                    uint32_t bits;
                    if(!take(bits))return false;
                    lane=constant(bits);
                }

                return true;
            }

            uint32_t kind=(t>>12)&0xff;
            uint32_t mode=(t>>2)&3;

            if(kind!=0 || mode==3 ||
               (t&3)!=2)
                return false;

            uint32_t base=0x00100002u|
                          (mode<<2);

            uint32_t selectionMask=
                mode==0?0xf0u:
                mode==1?0xff0u:0x30u;

            if((t&~selectionMask)!=base)
                return false;

            uint32_t r;

            if(!take(r) || r>=tempCount)
                return false;

            if(mode==0 && ((t>>4)&15)!=15)
                return false;

            for(unsigned i=0;i<4;++i){

                unsigned lane=i;

                if(mode==1)
                    lane=(t>>(4+2*i))&3;

                if(mode==2)
                    lane=(t>>4)&3;

                v[i]=temps[r][lane];
            }

            return true;
        };

        std::array<Vec,3> args{};

        for(unsigned i=0;i<sources;++i)
            if(!source(args[i]))return {};

        if(pc!=end)return {};

        Vec updated=*target;

        for(unsigned i=0;i<4;++i){

            if(!(mask&(1u<<i)))continue;

            for(unsigned j=0;j<sources;++j)
                if(!args[j][i])return {};

            uint32_t a=args[0][i];
            uint32_t b=args[1][i];
            uint32_t c=args[2][i];

            switch(op){

                case 54:
                    updated[i]=a;
                    break;

                case 0:
                    updated[i]=binary(129,a,b);
                    break;

                case 56:
                    updated[i]=binary(133,a,b);
                    break;

                case 50:
                    updated[i]=binary(
                        129,binary(133,a,b),c);
                    break;

                case 51:
                    updated[i]=ext(79,a,b);
                    break;

                case 52:
                    updated[i]=ext(80,a,b);
                    break;
            }
        }

        *target=updated;
    }

    if(!returned)return {};

    for(auto lane:output)
        if(!lane)return {};

    uint32_t color=id();

    emit(body,80,{
        4,color,
        output[0],output[1],
        output[2],output[3]
    });

    emit(body,62,{6,color});
    emit(body,253,{});
    emit(body,56,{});

    result={0x07230203,0x00010000,0,next,0};

    emit(result,17,{1});

    emit(result,11,{
        9,0x4c534c47,
        0x6474732e,0x3035342e,0
    });

    emit(result,14,{0,1});
    emit(result,15,{4,7,0x6e69616d,0,6});
    emit(result,16,{7,7});
    emit(result,71,{6,30,0});

    emit(result,19,{1});
    emit(result,33,{2,1});
    emit(result,22,{3,32});
    emit(result,23,{4,3,4});
    emit(result,32,{5,3,4});

    result.insert(result.end(),
        declarations.begin(),declarations.end());

    emit(result,59,{5,6,3});

    emit(result,54,{1,7,0,2});
    emit(result,248,{8});

    result.insert(result.end(),
        body.begin(),body.end());

    return result;
}

}
