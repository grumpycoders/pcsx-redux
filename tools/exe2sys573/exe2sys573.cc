/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include <stdint.h>
#include <string.h>

#include <filesystem>
#include <map>
#include <string>
#include <system_error>
#include <vector>

#include "flags.h"
#include "fmt/format.h"
#include "support/file.h"
#include "support/mem4g.h"
#include "supportpsx/binloader.h"

// The System 573 shell boots from the onboard flash or a PCMCIA flash card when
// DIP switch 4 is on. Both use the same layout:
//   0x00  32 bytes, not read by the shell (left erased)
//   0x20  CRC32 of the executable, little endian
//   0x24  standard PS-EXE, 2048-byte header included
// The CRC only covers the bytes of the executable at offsets 0, 1, 2, 4, 8 and
// so on, up to the header's text size. The shell uses the text size alone as the
// length, so the last 2048 bytes of the executable are never checked.
static uint32_t crc573(const std::vector<uint8_t>& data, uint32_t length) {
    uint32_t crc = 0xffffffff;
    uint32_t offset = 0;
    while (offset < length) {
        crc ^= data[offset];
        for (unsigned bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        }
        offset = offset ? offset << 1 : 1;
    }
    return ~crc;
}

static void put32(std::vector<uint8_t>& data, size_t offset, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) data[offset + i] = value >> (i * 8);
}

static bool writeFile(const std::string& name, const uint8_t* data, size_t size) {
    PCSX::IO<PCSX::File> out = new PCSX::PosixFile(name.c_str(), PCSX::FileOps::TRUNCATE);
    if (out->failed()) {
        fmt::print("Unable to open output file: {}\n", name);
        return false;
    }
    if (out->write(data, size) != static_cast<ssize_t>(size)) {
        fmt::print("Unable to write output file: {}\n", name);
        return false;
    }
    fmt::print("File {} created.\n", name);
    return true;
}

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    auto output = args.get<std::string>("o");
    auto even = args.get<std::string>("even");
    auto odd = args.get<std::string>("odd");
    const bool pad = args.get<bool>("pad").value_or(false);

    fmt::print(R"(
exe2sys573
https://github.com/grumpycoders/pcsx-redux/tree/main/tools/exe2sys573/
)");

    const auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool hasSplit = even.has_value() && odd.has_value();
    const bool halfSplit = even.has_value() != odd.has_value();
    const bool hasOutput = output.has_value() || hasSplit;
    const bool oneInput = inputs.size() == 1;
    if (asksForHelp || !oneInput || !hasOutput || halfSplit) {
        fmt::print(R"(
Usage: {} input.ps-exe [-h] [-o output.bin] [-even even.bin -odd odd.bin] [-pad]
  input.ps-exe   mandatory: specify the input binary file.
  -o output.bin  name of the output flash image.
  -even even.bin name of the output file for the even bytes of the image.
  -odd odd.bin   name of the output file for the odd bytes of the image.
  -pad           pad the even and odd files to 2MB each with 0xff.
  -h             displays this help information and exit.

At least one of -o, or -even and -odd together, is required.

The output is a System 573 flash image, bootable from either the onboard
flash or a PCMCIA flash card with DIP switch 4 on. The even and odd files
are the byte-interleaved halves of the same image, as found on a pair of
flash chips (in MAME, 29f016a.31m and 29f016a.27m for the onboard flash).

Valid input binary files can be in the following formats:
 - PS-EXE (needs the "PS-X EXE" signature)
 - ELF
 - CPE
 - PSF
 - MiniPSF
)",
                   argv[0]);
        return -1;
    }

    std::vector<std::filesystem::path> outputs;
    if (output.has_value()) outputs.push_back(output.value());
    if (hasSplit) {
        outputs.push_back(even.value());
        outputs.push_back(odd.value());
    }
    for (auto& path : outputs) {
        std::error_code ec;
        auto normal = std::filesystem::weakly_canonical(path, ec);
        path = ec ? path.lexically_normal() : normal;
    }
    for (size_t i = 0; i < outputs.size(); i++) {
        for (size_t j = i + 1; j < outputs.size(); j++) {
            if (outputs[i] == outputs[j]) {
                fmt::print("Output files must be distinct: {}\n", outputs[i].string());
                return -1;
            }
        }
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

    uint32_t tload = memory->lowestAddress();
    uint32_t pc = info.pc.value_or(0);
    uint32_t gp = info.gp.value_or(0);
    uint32_t sp = info.sp.value_or(0);

    if ((tload & 3) || (pc & 3) || (gp & 3) || (sp & 3)) {
        fmt::print("File {} is invalid: tload, pc, gp and sp must be aligned to 4 bytes.\n", input);
        return -1;
    }

    uint32_t size = memory->actualSize();
    size = (size + 2047) & ~2047;

    // The shell only maps the first 4MB bank of the flash.
    constexpr size_t bankSize = 0x400000;
    if (0x24 + 2048 + size > bankSize) {
        fmt::print("File {} is too large: the image must fit in 4MB.\n", input);
        return -1;
    }

    std::vector<uint8_t> exe(2048 + size, 0);
    memcpy(exe.data(), "PS-X EXE", 8);
    put32(exe, 0x10, pc);
    put32(exe, 0x14, gp);
    put32(exe, 0x18, tload);
    put32(exe, 0x1c, size);
    put32(exe, 0x30, sp);
    auto data = memory.asA<PCSX::File>()->readAt(size, tload);
    if (data.size() != size) {
        fmt::print("File {} is invalid: the payload runs past the end of the address space.\n", input);
        return -1;
    }
    memcpy(exe.data() + 2048, data.data(), size);

    uint32_t crc = crc573(exe, size);

    std::vector<uint8_t> image(0x24, 0xff);
    put32(image, 0x20, crc);
    image.insert(image.end(), exe.begin(), exe.end());

    fmt::print(R"(
Input file: {}
pc: 0x{:08x}  gp: 0x{:08x}  sp: 0x{:08x}  crc: 0x{:08x}

)",
               input, pc, gp, sp, crc);

    if (output.has_value() && !writeFile(output.value(), image.data(), image.size())) return -1;

    if (hasSplit) {
        if (pad) {
            image.resize(bankSize, 0xff);
        } else if (image.size() & 1) {
            image.push_back(0xff);
        }
        std::vector<uint8_t> evenBytes, oddBytes;
        for (size_t i = 0; i < image.size(); i += 2) {
            evenBytes.push_back(image[i]);
            oddBytes.push_back(image[i + 1]);
        }
        if (!writeFile(even.value(), evenBytes.data(), evenBytes.size())) return -1;
        if (!writeFile(odd.value(), oddBytes.data(), oddBytes.size())) return -1;
    }

    fmt::print("All done.\n");

    return 0;
}
