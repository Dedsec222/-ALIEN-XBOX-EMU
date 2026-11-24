#pragma once
#include "guest_memory64.hpp"

namespace genesis {
// Gregorian March-based civil calendar. A 400-year cycle contains 146097 days.
inline unsigned convertGuestTime(GuestMemory64& memory,uint64_t from,uint64_t to,bool toCalendar) {
    constexpr uint64_t dayMillis=86400000;
    constexpr int epoch=584694; // days preceding 1601-01-01, from March of year zero
    using Fault=GuestMemory64::Fault;
    std::array<uint16_t,8> fields{};
    uint64_t ticks=0;
    auto bytes=[](auto& value) {
        return std::span<uint8_t>(reinterpret_cast<uint8_t*>(&value),sizeof(value));
    };
    if (toCalendar) {
        if (memory.read(from,bytes(ticks))!=Fault::none) return 998;
        if (ticks>>63) return 87;
        const auto ms=ticks/10000;
        const unsigned day=unsigned(ms/dayMillis);
        const unsigned z=day+epoch;
        const unsigned era=z/146097, doe=z%146097;
        const unsigned yoe=(doe-doe/1460+doe/36524-doe/146096)/365;
        const unsigned doy=doe-(365*yoe+yoe/4-yoe/100);
        const unsigned mp=(5*doy+2)/153;
        fields={uint16_t(era*400+yoe+(mp>=10)),uint16_t(mp<10?mp+3:mp-9),
                uint16_t((day+1)%7),uint16_t(doy-(153*mp+2)/5+1),
                uint16_t(ms/3600000%24),uint16_t(ms/60000%60),uint16_t(ms/1000%60),uint16_t(ms%1000)};
        return memory.write(to,bytes(fields))==Fault::none?0:998;
    }
    if (memory.read(from,bytes(fields))!=Fault::none) return 998;
    auto [year,month,weekday,day,hour,minute,second,millis]=fields;
    (void)weekday;
    const bool leap=year%4==0 && (year%100!=0 || year%400==0);
    const unsigned lengths[]={31,28u+leap,31,30,31,30,31,31,30,31,30,31};
    if (year<1601 || year>30827 || month<1 || month>12 || day<1 ||
        day>lengths[month-1] || hour>=24 || minute>=60 || second>=60 || millis>=1000) return 87;
    const unsigned y=year-(month<=2), mp=month>2?month-3:month+9;
    const unsigned days=365*y+y/4-y/100+y/400+(153*mp+2)/5+day-1-epoch;
    ticks=(days*dayMillis+hour*3600000u+minute*60000u+second*1000u+millis)*10000u;
    return memory.write(to,bytes(ticks))==Fault::none?0:998;
}
}
