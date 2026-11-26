#pragma once
#include "scarlett_dxbc.hpp"
#include "scarlett_shader_alu.hpp"
#include <array>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <vector>

namespace genesis {
// A tokenized SHDR program with one float4 render target at location zero.
// The caller supplies this output signature. Other signatures require linkage.
inline std::vector<uint32_t> translateConstantPixel(std::span<const uint32_t> code) {
    constexpr uint32_t output=0x001020f2; // o0.xyzw, immediate 1D index
    constexpr uint32_t literal=0x00004002;
    if (code.size()!=14 || (code[0]!=0x40 && code[0]!=0x50) || code[1]!=code.size() ||
        code[2]!=0x03000065 || code[3]!=output || code[4]!=0 || // dcl_output
        code[5]!=0x08000036 || code[6]!=output || code[7]!=0 || code[8]!=literal || // mov
        code[13]!=0x0100003e) return {}; // ret
    std::vector<uint32_t> spv={0x07230203,0x00010000,0,15,0};
    auto emit=[&](unsigned opcode,std::initializer_list<uint32_t> operands) {
        spv.push_back((uint32_t(operands.size()+1)<<16)|opcode);
        spv.insert(spv.end(),operands);
    };
    emit(17,{1});                         // OpCapability Shader
    emit(14,{0,1});                       // OpMemoryModel Logical GLSL450
    emit(15,{4,12,0x6e69616d,0,6});      // OpEntryPoint Fragment %12 "main" %6
    emit(16,{12,7});                      // OriginUpperLeft
    emit(71,{6,30,0});                    // Location 0
    emit(19,{1});                         // void
    emit(33,{2,1});                       // void()
    emit(22,{3,32});                      // float
    emit(23,{4,3,4});                     // vec4
    emit(32,{5,3,4});                     // ptr Output vec4
    emit(59,{5,6,3});                     // output variable
    for(unsigned i=0;i<4;++i)emit(43,{3,7+i,code[9+i]});
    emit(44,{4,11,7,8,9,10});             // constant composite
    emit(54,{1,12,0,2});                  // main
    emit(248,{13});                       // label
    emit(62,{6,11});                      // store
    emit(253,{});                         // return
    emit(56,{});                          // function end
    return spv;
}
constexpr std::array<uint32_t,14> greenPixel={
    0x40,14,0x03000065,0x001020f2,0,0x08000036,0x001020f2,0,0x00004002,
    0,0x3f800000,0,0x3f800000,0x0100003e
};

inline std::vector<uint32_t> translateDxbcPixel(
    std::span<const uint8_t> data){

    DxbcContainer container;

    if(!container.parse(data))
        return {};

    auto code=container.shader(data);

    if(code.empty())
        return {};

    auto constant=translateConstantPixel(code);

    if(!constant.empty())
        return constant;

    return translateArithmeticPixel(code);
}

}
