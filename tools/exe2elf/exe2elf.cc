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

#include "elfio/elfio.hpp"
#include "flags.h"
#include "fmt/format.h"
#include "support/file.h"
#include "support/mem4g.h"
#include "supportpsx/binloader.h"

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

    PCSX::BinaryLoader::Info info;
    PCSX::IO<PCSX::Mem4G> memory(new PCSX::Mem4G());
    std::map<uint32_t, std::string> symbols;
    bool success = PCSX::BinaryLoader::load(file, memory, info, symbols);
    if (!success) {
        fmt::print("Unable to load file: {}\n", input);
        return -1;
    }
    if (!info.pc.has_value()) {
        fmt::print("File {} is invalid.\n", input);
        return -1;
    }

    std::vector<uint8_t> dataIn;
    dataIn.resize(memory->actualSize());
    memory->readAt(dataIn.data(), dataIn.size(), memory->actualSize());
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
    text->set_address(memory->lowestAddress());

    writer.set_entry(info.pc.value());

    writer.save(output.value());

    fmt::print("File {} created. All done.\n", output.value());

    return 0;
}
