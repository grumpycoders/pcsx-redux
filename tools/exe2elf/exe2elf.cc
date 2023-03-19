/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

#include "ELFIO/elfio.hpp"
#include "flags.h"
#include "fmt/format.h"
#include "support/binstruct.h"
#include "support/file.h"
#include "support/typestring-wrapper.h"

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

constexpr uint64_t PSEXE = 0x45584520582d5350;

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    auto output = args.get<std::string>("o");

    fmt::print(R"(
exe2elf by Nicolas "Pixel" Noble
https://github.com/grumpycoders/pcsx-redux/tree/main/tools/exe2elf/
)");

    auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool hasOutput = output.has_value();
    const bool oneInput = inputs.size() == 1;
    if (asksForHelp || !oneInput || !hasOutput) {
        fmt::print(R"(
Usage: {} input.ps-exe [-h] -o output.elf
  input.ps-exe      mandatory: specify the input ps-exe file.
  -o output.elf     mandatory: name of the output file.
  -h                displays this help information and exit.
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
    ELFIO::elfio writer;

    writer.create(ELFCLASS32, ELFDATA2LSB);
    writer.set_os_abi(ELFOSABI_NONE);
    writer.set_type(ET_EXEC);
    writer.set_machine(EM_MIPS);

    ELFIO::section* text = writer.sections.add(".text");
    text->set_type(SHT_PROGBITS);
    text->set_flags(SHF_ALLOC | SHF_EXECINSTR);
    text->set_addr_align(4);
    text->set_data(reinterpret_cast<char*>(dataIn.data()), dataIn.size());
    text->set_address(addr);

    writer.set_entry(pc);

    writer.save(output.value());

    fmt::print("File {} created. All done.\n", output.value());

    return 0;
}
