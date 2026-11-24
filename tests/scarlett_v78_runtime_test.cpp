#include "scarlett_launch.hpp"
#include <cassert>
#include <fstream>
using namespace genesis;
int main(){
    using F=GuestMemory64::Fault;
    GuestMemory64 mem;
    ScarlettImports64 imports;
    assert(imports.install(mem) && mem.map(0x1000,4096,3)==F::none);
    auto call=[&](std::string dll,std::string name,uint64_t a=0,uint64_t b=0,uint64_t c=0,uint64_t d=0){
        uint64_t ret=0;
        auto stub=imports.registerImport(dll,name);
        assert(stub && imports.dispatch(stub,mem,a,ret,b,c,d));
        return ret;
    };
    for(auto n:{"htons","ntohs","#9","#15"}) assert(call("WS2_32.dll",n,0x11223344)==0x4433);
    for(auto n:{"htonl","ntohl","#8","#14"}) assert(call("WS2_32.dll",n,0x11223344)==0x44332211);
    auto view=[](auto& v){return std::span(reinterpret_cast<uint8_t*>(&v),sizeof(v));};
    std::string tz="api-ms-win-core-timezone-l1-1-0.dll";
    for(auto year:{1601,1700,1900,1970,2000,2100,30827}){
        const bool leap=year%4==0 && (year%100!=0 || year%400==0);
        std::array<uint16_t,8> date={uint16_t(year),2,0,uint16_t(leap?29:28),23,59,59,999},out{};
        assert(mem.write(0x1000,view(date))==F::none);
        assert(call(tz,"SystemTimeToFileTime",0x1000,0x1020)==1 && call(tz,"FileTimeToSystemTime",0x1020,0x1040)==1);
        assert(mem.read(0x1040,view(out))==F::none);
        assert(out[2]<=6);out[2]=0;assert(date==out);
        date[3]=30;
        assert(mem.write(0x1000,view(date))==F::none && call(tz,"SystemTimeToFileTime",0x1000,0x1020)==0);
    }
    uint64_t unixEpoch=116444736000000000ULL;
    assert(mem.write(0x1020,view(unixEpoch))==F::none && call(tz,"FileTimeToSystemTime",0x1020,0x1040));
    std::array<uint16_t,8> date{};
    assert(mem.read(0x1040,view(date))==F::none && date[0]==1970 && date[1]==1 && date[2]==4 && date[3]==1);
    const std::string timeDll="api-ms-win-crt-time-l1-1-0.dll";
    int64_t epoch=0;
    assert(mem.write(0x1100,view(epoch))==F::none);
    std::array<int32_t,9> fields{};
    for(auto n:{"_gmtime64_s","_localtime64_s"}) {
        assert(call(timeDll,n,0x1200,0x1100)==0 && mem.read(0x1200,view(fields))==F::none);
        assert((fields==std::array<int32_t,9>{0,0,0,1,0,70,4,0,0}));
    }
    assert(mem.map(ScarlettRuntime64::Teb,4096,3)==F::none);
    assert(ScarlettRuntime64::put64(mem,ScarlettRuntime64::Teb+8,0x9000));
    assert(ScarlettRuntime64::put64(mem,ScarlettRuntime64::Teb+16,0x8000));
    call("api-ms-win-core-processthreads-l1-1-1.dll","GetCurrentThreadStackLimits",0x1200,0x1208);
    uint64_t lo,hi;
    assert(mem.read(0x1200,view(lo))==F::none && lo==0x8000);
    assert(mem.read(0x1208,view(hi))==F::none && hi==0x9000);
    call(timeDll,"_ftime64",0x1200);
    assert(mem.read(0x1200,view(epoch))==F::none && epoch>0);
    const std::string io="api-ms-win-crt-stdio-l1-1-0.dll";
    assert(mem.write(0x1100,std::array<uint8_t,4>{'a','b','c',0})==F::none);
    assert(mem.write(0x1110,std::array<uint8_t,4>{'w','b','+',0})==F::none);
    auto h=call(io,"fopen",0x1100,0x1110);
    assert(h && call(io,"fwrite",0x1100,1,3,h)==3 && call(io,"ftell",h)==3);
    assert(call(io,"_fseeki64",h,uint64_t(-1),2)==0 && call(io,"fgetc",h)=='c');
    assert(call(io,"fgetc",h)==UINT32_MAX && call(io,"rewind",h)==0);
    assert(call(io,"fputc",'z',h)=='z' && call(io,"fflush",h)==0 && call(io,"fseek",h,0,0)==0);
    std::array<uint8_t,3> data{};
    assert(call(io,"fread",0x1200,1,8,h)==3 && mem.read(0x1200,data)==F::none);
    assert((data==std::array<uint8_t,3>{'z','b','c'}));
    assert(call(io,"fclose",h)==0 && call(io,"fclose",h)==UINT32_MAX);
    std::ifstream f("app/src/main/assets/doors.exe",std::ios::binary);
    std::vector<uint8_t> file{std::istreambuf_iterator<char>(f),{}};
    auto result=launchScarlett(file,1000);
    assert(result.find("Guest breakpoint")==0);
    std::cout<<result<<"\n";
}
