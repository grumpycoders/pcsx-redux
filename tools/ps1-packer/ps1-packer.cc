/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include <assert.h>
#include <memory.h>
#include <stdint.h>

#include <vector>

#include "flags.h"
#include "fmt/format.h"
#include "mips/common/util/encoder.hh"
#include "n2e-d.h"
#include "support/binstruct.h"
#include "support/file.h"
#include "support/typestring-wrapper.h"
#include "ucl/ucl.h"

typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt64, TYPESTRING("id")> PSExe_ID;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("text")> PSExe_Text;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("data")> PSExe_Data;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("pc")> PSExe_PC;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("gp")> PSExe_GP;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("text_addr")> PSExe_TextAddr;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("text_size")> PSExe_TextSize;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("data_addr")> PSExe_DataAddr;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("data_size")> PSExe_DataSize;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("bss_addr")> PSExe_BssAddr;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("bss_size")> PSExe_BssSize;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("stack_addr")> PSExe_StackAddr;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("stack_size")> PSExe_StackSize;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("saved_sp")> PSExe_SavedSP;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("saved_fp")> PSExe_SavedFP;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("saved_gp")> PSExe_SavedGP;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("saved_ra")> PSExe_SavedRA;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("saved_s0")> PSExe_SavedS0;
typedef PCSX::BinStruct::Struct<TYPESTRING("PSExeHeader"), PSExe_ID, PSExe_Text, PSExe_Data, PSExe_PC, PSExe_GP,
                                PSExe_TextAddr, PSExe_TextSize, PSExe_DataAddr, PSExe_DataSize, PSExe_BssAddr,
                                PSExe_BssSize, PSExe_StackAddr, PSExe_StackSize, PSExe_SavedSP, PSExe_SavedFP,
                                PSExe_SavedGP, PSExe_SavedRA, PSExe_SavedS0>
    PSExe_Header;

using namespace Mips::Encoder;

constexpr uint64_t PSEXE = 0x45584520582d5350;

extern "C" {
ucl_voidp ucl_memcpy(ucl_voidp dest, const ucl_voidp src, ucl_uint len) { return memcpy(dest, src, len); }
ucl_voidp ucl_memset(ucl_voidp s, int c, ucl_uint len) { return memset(s, c, len); }
}

template <typename T>
void pushBytes(std::vector<uint8_t>& data, T value) {
    for (unsigned i = 0; i < sizeof(T); i++) {
        data.push_back(value & 0xff);
        value >>= 8;
    }
}

static int16_t getHI(uint32_t v) {
    int16_t lo = v & 0xffff;
    int16_t hi = v >> 16;
    return lo < 0 ? hi + 1 : hi;
}

static int16_t getLO(uint32_t v) {
    int16_t ret = v & 0xffff;
    return ret;
}

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    auto output = args.get<std::string>("o");

    fmt::print(R"(
ps1-packer by Nicolas "Pixel" Noble
https://github.com/grumpycoders/pcsx-redux/tree/main/tools/ps1-packer/
)");

    auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool hasOutput = output.has_value();
    const uint32_t tload = std::stoul(args.get<std::string>("tload").value_or("0"), nullptr, 0);
    const bool oneInput = inputs.size() == 1;
    const bool shell = args.get<bool>("shell").value_or(false);
    const bool booty = args.get<bool>("booty").value_or(false);
    if (asksForHelp || !oneInput || !hasOutput) {
        fmt::print(R"(
Usage: {} input.ps-exe [-h] [-tload addr] [-shell | -booty] -o output.ps-exe
  input.ps-exe      mandatory: specify the input ps-exe file.
  -o output.ps-exe  mandatory: name of the output file.
  -h                displays this help information and exit.
  -tload            force loading at this address instead of doing in-place.
  -shell            adds a kernel reset stub; see documentation for details.
  -booty            outputs a counter-booty payload.
)",
                   argv[0]);
        return -1;
    }

    auto& input = inputs[0];
    PCSX::IO<PCSX::File> file(new PCSX::PosixFile(input));
    if (file->failed()) {
        fmt::print("Unable to open file: {}\n", input);
        return -1;
    }

    PSExe_Header inHeader;
    inHeader.deserialize(file);

    if (inHeader.get<PSExe_ID>() != PSEXE) {
        fmt::print("File {} isn't a valid ps-exe\n", input);
        return -1;
    }

    uint32_t pc = inHeader.get<PSExe_PC>();
    uint32_t gp = inHeader.get<PSExe_GP>();
    uint32_t addr = inHeader.get<PSExe_TextAddr>();
    uint32_t size = inHeader.get<PSExe_TextSize>();
    uint32_t bssAddr = inHeader.get<PSExe_BssAddr>();
    uint32_t bssSize = inHeader.get<PSExe_BssSize>();
    uint32_t sp = inHeader.get<PSExe_StackAddr>();
    sp += inHeader.get<PSExe_StackSize>();
    if (sp == 0) sp = 0x801fff00;

    file->rSeek(2048, SEEK_SET);

    std::vector<uint8_t> dataIn;
    dataIn.resize(size);
    file->read(dataIn.data(), dataIn.size());
    file.reset();
    while ((dataIn.size() & 3) != 0) dataIn.push_back(0);

    std::vector<uint8_t> dataOut;
    dataOut.resize(dataIn.size() * 1.2 + 2048);
    ucl_uint outSize;
    int r;

    r = ucl_nrv2e_99_compress(dataIn.data(), dataIn.size(), dataOut.data(), &outSize, nullptr, 10, nullptr, nullptr);
    if (r != UCL_E_OK) {
        fmt::print("Fatal error during data compression.\n");
        return -1;
    }
    dataOut.resize(outSize);
    pushBytes<uint32_t>(dataOut, 0xdeadbeef);
    uint32_t newPC;
    uint32_t compLoad;
    bool inplace;

    if (tload != 0) {
        while ((dataOut.size() & 3) != 0) dataOut.push_back(0);
        compLoad = tload;
        newPC = compLoad + dataOut.size();
        inplace = false;
    } else {
        newPC = addr + dataIn.size() + 16;
        compLoad = newPC - dataOut.size();
        inplace = true;
    }
    newPC += sizeof(n2e_d::code);
    assert((newPC & 3) == 0);

    for (auto b : n2e_d::code) pushBytes(dataOut, b);

    pushBytes(dataOut, lui(Reg::V1, 0x1f00));
    pushBytes(dataOut, sw(Reg::R0, 0x1074, Reg::V1));
    pushBytes(dataOut, lui(Reg::A0, getHI(compLoad)));
    pushBytes(dataOut, addiu(Reg::A0, Reg::A0, getLO(compLoad)));
    pushBytes(dataOut, lui(Reg::A1, getHI(addr)));
    pushBytes(dataOut, bgezal(Reg::R0, -((int16_t)(sizeof(n2e_d::code) + 6 * 4))));
    pushBytes(dataOut, addiu(Reg::A1, Reg::A1, getLO(addr)));
    if (shell) {
        pushBytes(dataOut, bgezal(Reg::R0, 36));
        pushBytes(dataOut, addiu(Reg::S0, Reg::R0, 0xa0));
        // this goes to 0x40
        pushBytes(dataOut, 0x40803800);  // mtc0 $0, $t7
        pushBytes(dataOut, jr(Reg::RA));
        pushBytes(dataOut, 0x42000010);  // rfe
        // this goes to 0x80030000
        pushBytes(dataOut, lui(Reg::T0, getHI(pc)));
        pushBytes(dataOut, addiu(Reg::T0, Reg::T0, getLO(pc)));
        pushBytes(dataOut, lui(Reg::GP, getHI(gp)));
        pushBytes(dataOut, jr(Reg::T0));
        pushBytes(dataOut, addiu(Reg::GP, Reg::GP, getLO(gp)));
        // copying stuff around
        pushBytes(dataOut, addiu(Reg::S1, Reg::RA, 0));

        pushBytes(dataOut, addiu(Reg::A0, Reg::R0, 0x40));
        pushBytes(dataOut, addiu(Reg::A1, Reg::S1, 0));
        pushBytes(dataOut, addiu(Reg::A2, Reg::R0, 12));
        pushBytes(dataOut, jalr(Reg::S0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x2a));

        pushBytes(dataOut, lui(Reg::A0, 0x8003));
        pushBytes(dataOut, addiu(Reg::A1, Reg::S1, 12));
        pushBytes(dataOut, addiu(Reg::A2, Reg::R0, 20));
        pushBytes(dataOut, jalr(Reg::S0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x2a));

        constexpr uint32_t partialReboot = 0xbfc00390;

        pushBytes(dataOut, lui(Reg::RA, getHI(partialReboot)));
        pushBytes(dataOut, addiu(Reg::RA, Reg::RA, getLO(partialReboot)));

        pushBytes(dataOut, lui(Reg::T0, 0b1100101010000000));
        pushBytes(dataOut, lui(Reg::T1, 0x8003));
        pushBytes(dataOut, addiu(Reg::T2, Reg::R0, -1));
        pushBytes(dataOut, 0x40883800);  // mtc0 $t0, $7
        pushBytes(dataOut, 0x40892800);  // mtc0 $t1, $5
        pushBytes(dataOut, 0x408a4800);  // mtc0 $t2, $9

        pushBytes(dataOut, jr(Reg::S0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x44));
    } else {
        pushBytes(dataOut, addiu(Reg::T0, Reg::R0, 0xa0));
        pushBytes(dataOut, lui(Reg::RA, getHI(pc)));
        pushBytes(dataOut, addiu(Reg::RA, Reg::RA, getLO(pc)));
        pushBytes(dataOut, jr(Reg::T0));
        pushBytes(dataOut, addiu(Reg::T1, Reg::R0, 0x44));
    }
    while (!booty && ((dataOut.size() & 0x7ff) != 0)) dataOut.push_back(0);
    while ((dataOut.size() & 3) != 0) dataOut.push_back(0);

    std::vector<uint8_t> header;
    if (booty) {
        std::vector<uint32_t> stage2;
        /* 0x24 */ stage2.push_back(lw(Reg::A3, 0, Reg::A1));
        /* 0x28 */ stage2.push_back(addiu(Reg::A2, Reg::A2, -1));
        /* 0x2c */ stage2.push_back(sw(Reg::A3, 0, Reg::A0));
        /* 0x30 */ stage2.push_back(bne(Reg::A2, Reg::R0, -16));
        /* 0x34 */ stage2.push_back(addiu(Reg::A0, Reg::A0, 4));
        /* 0x38 */ stage2.push_back(j(0xa0));
        /* 0x3c */ stage2.push_back(addiu(Reg::T1, Reg::R0, 0x44));
        /* 0x40 */ stage2.push_back(mtc0(Reg::R0, 7));
        /* 0x44 */ stage2.push_back(lui(Reg::A0, compLoad >> 16));
        if ((compLoad & 0xffff) != 0) {
            /* 0x48 */ stage2.push_back(ori(Reg::A0, Reg::A0, compLoad));
        }
        /* 0x4c */ stage2.push_back(lui(Reg::RA, newPC >> 16));
        if ((newPC & 0xffff) != 0) {
            /* 0x50 */ stage2.push_back(ori(Reg::RA, Reg::RA, newPC));
        }
        /* 0x54 */ stage2.push_back(lui(Reg::A1, 0xbf00));
        /* 0x58 */ stage2.push_back(j(0x24));
        /* 0x5c */ stage2.push_back(ori(Reg::A2, Reg::R0, dataOut.size() / 4));

        static constexpr uint8_t license[] = {
            0x4c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x53, 0x6f, 0x6e, 0x79,
            0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x45, 0x6e, 0x74, 0x65, 0x72, 0x74,
            0x61, 0x69, 0x6e, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x2e, 0x00, 0x00, 0x00, 0x1f,
        };

        for (auto b : license) {
            pushBytes(header, b);
        }

        // break on writes and/or exec
        pushBytes(header, mtc0(Reg::R0, 7));
        pushBytes(header, addiu(Reg::T2, Reg::R0, 0xffff));
        pushBytes(header, lui(Reg::T1, 0x8003));
        pushBytes(header, lui(Reg::T0, 0xeb80));
        pushBytes(header, mtc0(Reg::T2, 11));
        pushBytes(header, mtc0(Reg::T2, 9));
        pushBytes(header, mtc0(Reg::T1, 5));
        pushBytes(header, mtc0(Reg::T1, 3));
        pushBytes(header, mtc0(Reg::T0, 7));

        int16_t base = 0x24;
        uint32_t last = 0;
        for (auto b : stage2) {
            pushBytes(header, lui(Reg::T0, b >> 16));
            uint16_t rest = b;
            if (rest != 0) {
                pushBytes(header, ori(Reg::T0, Reg::T0, rest));
            }
            last = sw(Reg::T0, base, Reg::R0);
            pushBytes(header, last);
            base += 4;
        }
        header.pop_back();
        header.pop_back();
        header.pop_back();
        header.pop_back();
        pushBytes(header, jr(Reg::RA));
        pushBytes(header, last);
    } else {
        pushBytes(header, PSEXE);
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes(header, newPC);
        pushBytes(header, gp);
        pushBytes(header, compLoad);
        pushBytes(header, dataOut.size());
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes<uint32_t>(header, 0);
        pushBytes(header, sp);
        while (header.size() < 0x800) header.push_back(0);
    }

    fmt::print(R"(
Input file: {}
pc: 0x{:08x}  gp: 0x{:08x}  sp: 0x{:08x}
bss: {}@0x{:08x}
code size: {} -> {}
loading address: 0x{:08x}
inplace decompression: {}
booty bytestream: {}

new pc: 0x{:08x}
)",
               input, pc, gp, sp, bssSize, bssAddr, dataIn.size(), dataOut.size(), compLoad, inplace ? "yes" : "no",
               booty ? "yes" : "no", newPC);

    if (bssSize != 0) fmt::print("Warning: bss not empty.\n");
    FILE* out = fopen(output.value().c_str(), "wb");
    if (!out) {
        fmt::print("Error opening output file {}\n", output.value());
        return -1;
    }

    fwrite(header.data(), header.size(), 1, out);
    fwrite(dataOut.data(), dataOut.size(), 1, out);

    fclose(out);

    fmt::print("File {} created. All done.\n", output.value());

    return 0;
}
