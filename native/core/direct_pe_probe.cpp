#include <cstring>
#include "direct_pe_loader.hpp"

#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr <<
            "Usage: direct_pe_probe <exe> [base]\n";
        return 1;
    }

    try {
        std::ifstream file(
            argv[1],
            std::ios::binary | std::ios::ate);

        if (!file)
            throw std::runtime_error("Open failed");

        const auto size = file.tellg();

        if (size <= 0 ||
            size > std::streamoff(2ULL << 30))
            throw std::runtime_error(
                "Invalid file size");

        std::vector<std::byte> bytes(
            static_cast<size_t>(size));

        file.seekg(0);

        if (!file.read(
            reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(
                bytes.size())))
            throw std::runtime_error("Read failed");

        auto pe = alien::Pe64Image::parse(bytes);

        const size_t sections = pe.sections.size();
        const uint64_t preferredBase=pe.image_base;
        const auto originalTls=pe.readTls(preferredBase);

        uint64_t requestedBase=preferredBase;

        if(argc==3)
            requestedBase=std::stoull(argv[2],nullptr,0);

        std::vector<std::byte> expectedTls;
        size_t tlsRelocations=0;

        if(originalTls){
            expectedTls=originalTls->initial_data;

            auto read=[&]<typename T>(uint64_t offset){
                if(offset>pe.image.size() ||
                   sizeof(T)>pe.image.size()-offset)
                    throw std::runtime_error(
                        "Relocation read out of bounds");

                T value{};
                std::memcpy(&value,
                    pe.image.data()+offset,sizeof(T));
                return value;
            };

            const uint64_t opt=
                uint64_t(read.operator()<uint32_t>(0x3c))+24;

            const uint32_t relocRva=
                read.operator()<uint32_t>(opt+152);

            const uint32_t relocSize=
                read.operator()<uint32_t>(opt+156);

            const uint64_t start=
                originalTls->template_start-preferredBase;

            const uint64_t end=start+expectedTls.size();

            const uint64_t delta=
                requestedBase-preferredBase;

            uint64_t pos=relocRva;
            const uint64_t limit=pos+relocSize;

            if(limit>pe.image.size())
                throw std::runtime_error(
                    "Invalid relocation directory");

            while(delta && pos<limit){

                if(limit-pos<8)
                    throw std::runtime_error(
                        "Truncated relocation block");

                const uint32_t pageRva=
                    read.operator()<uint32_t>(pos);

                const uint32_t blockSize=
                    read.operator()<uint32_t>(pos+4);

                if(blockSize<8 ||
                   blockSize>limit-pos ||
                   blockSize%2)
                    throw std::runtime_error(
                        "Invalid relocation block");

                for(uint64_t off=8;
                    off<blockSize;off+=2){

                    const uint16_t entry=
                        read.operator()<uint16_t>(pos+off);

                    const unsigned type=entry>>12;

                    if(type==0)
                        continue;

                    const uint64_t target=
                        uint64_t(pageRva)+(entry&0xfff);

                    if(type!=10)
                        throw std::runtime_error(
                            "Unsupported relocation type");

                    if(target>=end || target+8<=start)
                        continue;

                    if(target<start || target+8>end)
                        throw std::runtime_error(
                            "Partial TLS relocation");

                    const uint64_t index=target-start;

                    uint64_t before=0;

                    std::memcpy(&before,
                        expectedTls.data()+index,8);

                    const uint64_t after=before+delta;

                    std::memcpy(
                        expectedTls.data()+index,&after,8);

                    ++tlsRelocations;

                    std::cout << std::hex
                        << "TLS DIR64 offset: 0x" << index
                        << " pointer: 0x" << before
                        << " -> 0x" << after << '\n';
                }

                pos+=blockSize;
            }
        }



        std::vector<std::byte>().swap(bytes);

        uint64_t requested = 0;

        if (argc == 3)
            requested = std::stoull(
                argv[2], nullptr, 0);

        alien::DirectPeLoader loader;

        loader.load(std::move(pe), requested);

        std::cout << std::hex
            << "Mapped base: 0x" << loader.base()
            << "\nEntry VA: 0x" << loader.entry()
            << "\nImage size: 0x" << loader.size()
            << '\n';

        std::cout << "Entry bytes: ";

        for (unsigned i = 0; i < 16; ++i) {
            uint8_t value = 0;

            if (!loader.fetchByte(
                loader.entry() + i, value))
                break;

            std::cout << std::setw(2)
                << std::setfill('0')
                << unsigned(value) << ' ';
        }

        std::cout << std::dec
            << "\nSections: " << sections
            << "\nHost page size: "
            << alien::DirectGuestMemory::pageSize()
            << "\nResolved imports: "
            << loader.imports().resolved
            << "\nUnresolved imports: "
            << loader.imports().unresolved.size()
            << '\n';

        
        if(originalTls.has_value()!=loader.tls().has_value())
            throw std::runtime_error("TLS metadata mismatch");

        if(originalTls){
            const auto& original=*originalTls;
            const auto& tls=*loader.tls();

            const uint64_t delta=
                loader.base()-preferredBase;

            auto relocated=[&](uint64_t va){
                return va ? va+delta : uint64_t{0};
            };

            if(tls.template_start!=relocated(original.template_start) ||
               tls.template_end!=relocated(original.template_end) ||
               tls.index_address!=relocated(original.index_address) ||
               tls.callbacks_address!=relocated(original.callbacks_address))
                throw std::runtime_error("TLS relocation mismatch");


            if(tls.zero_fill!=original.zero_fill ||
               tls.characteristics!=original.characteristics ||
               tls.initial_data.size()!=original.initial_data.size())
                throw std::runtime_error("TLS metadata mismatch");


            if(tls.initial_data!=expectedTls)
                throw std::runtime_error(
                    "Relocated TLS template mismatch");

            std::cout << std::dec
                << "TLS DIR64 relocations verified: "
                << tlsRelocations << '\n';

            std::cout
                << "RELOCATION-AWARE TLS TEMPLATE PASSED\n";

            std::vector<std::byte> mapped(
                tls.initial_data.size());

            if(!mapped.empty() &&
               !loader.read(tls.template_start,
                            mapped.data(),mapped.size()))
                throw std::runtime_error("TLS template read failed");

            if(mapped!=tls.initial_data)
                throw std::runtime_error("Mapped TLS bytes mismatch");

            uint32_t oldIndex=0;
            const uint32_t testIndex=0x12345678;
            uint32_t actualIndex=0;

            if(!loader.read(tls.index_address,&oldIndex,4) ||
               !loader.write(tls.index_address,&testIndex,4) ||
               !loader.read(tls.index_address,&actualIndex,4) ||
               actualIndex!=testIndex ||
               !loader.write(tls.index_address,&oldIndex,4))
                throw std::runtime_error("TLS index access failed");

            std::cout << std::dec
                << "TLS template bytes: "
                << tls.initial_data.size()
                << "\nTLS zero-fill bytes: "
                << tls.zero_fill
                << "\nTLS callbacks: "
                << tls.callbacks.size()
                << '\n';

            for(size_t i=0;i<tls.callbacks.size();++i){
                const uint64_t callback=tls.callbacks[i];

                if(callback!=relocated(original.callbacks[i]))
                    throw std::runtime_error(
                        "TLS callback relocation mismatch");

                uint64_t mappedCallback=0;

                if(!loader.read(
                    tls.callbacks_address+i*8,
                    &mappedCallback,8) ||
                    mappedCallback!=callback)
                    throw std::runtime_error(
                        "Mapped callback pointer mismatch");

                uint8_t opcode=0;

                if(!loader.fetchByte(callback,opcode))
                    throw std::runtime_error(
                        "TLS callback not executable");

                std::cout << std::hex
                    << "Callback " << std::dec << i
                    << ": 0x" << std::hex << callback
                    << " opcode=0x" << unsigned(opcode)
                    << '\n';
            }

            if(tls.callbacks_address){
                uint64_t terminator=1;

                if(!loader.read(
                    tls.callbacks_address+
                    tls.callbacks.size()*8,
                    &terminator,8) || terminator)
                    throw std::runtime_error(
                        "TLS callback terminator invalid");
            }

            std::cout
                << "RAW PE TLS PARSING PASSED\n"
                << "MAPPED TLS TEMPLATE PASSED\n"
                << "TLS INDEX ACCESS PASSED\n"
                << "TLS CALLBACK POINTERS PASSED\n"
                << "TLS ADDRESS RELOCATION PASSED\n";
        }else{
            std::cout << "No static TLS directory\n";
        }

        const uint8_t test = 0;

        if (loader.write(
            loader.entry(), &test, 1))
            throw std::runtime_error(
                "Unexpected writable entry page");

        std::cout <<
            "Entry write protection: PASS\n"
            "DIRECT PE MAPPING PASSED\n"
            "Guest execution: NOT ATTEMPTED\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 2;
    }
}
