/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "flags.h"
#include "fmt/format.h"
#include "iec-60908b/edcecc.h"
#include "support/file.h"
#include "supportpsx/iec-60908b.h"

static void storeU32(uint32_t value, uint8_t* buffer) {
    buffer[0] = value & 0xff;
    buffer[1] = (value >> 8) & 0xff;
    buffer[2] = (value >> 16) & 0xff;
    buffer[3] = (value >> 24) & 0xff;
}

// make sure to call this with a sector that's memset to 0, as it relies on zeros being
// in the right place.
static void getSectorMinimal(uint8_t data[2048], uint32_t lba, uint32_t exeSize, uint32_t exeOffset = 19) {
    switch (lba) {
        // Minimal PVD
        case 16:
            data[0] = 1;
            data[1] = 'C';
            data[2] = 'D';
            data[3] = '0';
            data[4] = '0';
            data[5] = '1';
            storeU32(1, data + 132);
            storeU32(17, data + 140);
            storeU32(18, data + 158);
            break;
        // Minimal path table
        case 17:
            data[0] = 1;
            data[2] = 18;
            data[6] = 1;
            break;
        // Minimal root directory
        case 18:
            data[0] = 42;
            storeU32(exeOffset, data + 2);
            storeU32(exeSize, data + 10);
            data[32] = 9;
            data[33] = 'P';
            data[34] = 'S';
            data[35] = 'X';
            data[36] = '.';
            data[37] = 'E';
            data[38] = 'X';
            data[39] = 'E';
            data[40] = ';';
            data[41] = '1';
            break;
    }
}

// Call this once on a sector that's been memset to 0,
// in order to set all of the immutable data.
static void makeHeaderOnce(uint8_t sector[2352]) {
    memset(sector + 1, 0xff, 10);
    sector[15] = 2;
    sector[18] = sector[22] = 8;
}

// This function sets the LBA in the header of the sector.
static void makeHeader(uint8_t sector[2352], uint32_t lba) {
    PCSX::IEC60908b::MSF time(lba + 150);
    time.toBCD(sector + 12);
}

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);

    fmt::print(R"(
exe2iso by Nicolas "Pixel" Noble
https://github.com/grumpycoders/pcsx-redux/tree/main/tools/exe2iso/
)");

    const auto output = args.get<std::string>("o");
    const auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const uint32_t offset = std::stoul(args.get<std::string>("offset").value_or("0"), nullptr, 0);
    const bool hasOutput = output.has_value();
    const bool oneInput = inputs.size() == 1;
    const bool pad = args.get<bool>("pad").value_or(false);
    const bool regen = args.get<bool>("regen").value_or(false);
    const auto license = args.get<std::string>("license");
    const auto data = args.get<std::string>("data");
    if (asksForHelp || !oneInput || !hasOutput) {
        fmt::print(R"(
Usage: {} input.ps-exe [-offset value] [-pad] [-regen] [-license file] -o output.bin
  input.ps-exe      mandatory: specify the input ps-exe file.
  -o output.bin     mandatory: name of the output file.
  -offset value     optional: move the exe data by value sectors.
  -data filename    optional: insert this file into the iso after the exe.
  -pad              optional: pads the iso with 150 blank sectors.
  -regen            optional: generates proper ECC/EDC.
  -license file     optional: use this license file.
  -h                displays this help information and exit.
)",
                   argv[0]);
        return -1;
    }

    auto& input = inputs[0];
    PCSX::IO<PCSX::File> file(new PCSX::PosixFile(input));
    if (file->failed()) {
        fmt::print("Error opening input file {}\n", input);
        return -1;
    }
    PCSX::IO<PCSX::File> licenseFile(new PCSX::FailedFile);
    PCSX::IO<PCSX::File> dataFile(new PCSX::FailedFile);
    PCSX::IO<PCSX::File> out(new PCSX::PosixFile(output.value(), PCSX::FileOps::TRUNCATE));
    if (out->failed()) {
        fmt::print("Error opening output file {}\n", output.value());
        return -1;
    }
    if (license.has_value()) {
        licenseFile.setFile(new PCSX::PosixFile(license.value()));
        if (licenseFile->failed()) {
            fmt::print("Error opening license file {}\n", license.value());
            return -1;
        }
    }
    if (data.has_value()) {
        dataFile.setFile(new PCSX::PosixFile(data.value()));
        if (dataFile->failed()) {
            fmt::print("Error opening data file {}\n", data.value());
            return -1;
        }
    }

    uint32_t exeSize = file->size();
    exeSize += 2047;
    exeSize /= 2048;
    exeSize *= 2048;
    uint32_t exeOffset = 19 + offset;

    uint8_t sector[2352];
    memset(sector, 0, sizeof(sector));
    makeHeaderOnce(sector);
    bool wroteLicense = false;
    unsigned LBA = 0;
    auto writeSector = [&]() {
        makeHeader(sector, LBA++);
        if (regen) compute_edcecc(sector);
        out->write(sector, sizeof(sector));
    };
    // Sectors 0-15 are the license. We can keep it to zeroes and it'll work most everywhere.
    if (licenseFile && !licenseFile->failed()) {
        uint8_t licenseData[2352 * 16];
        memset(licenseData, 0, sizeof(licenseData));
        licenseFile->read(licenseData, sizeof(licenseData));
        if ((licenseFile->size() == 2336 * 16) && (licenseData[0x2492] == 'L')) {
            // official license file from the sdk, in 2336 bytes per sector.
            for (unsigned i = 0; i < 16; i++) {
                memcpy(sector + 16, licenseData + 2336 * i, 2336);
                writeSector();
            }
            wroteLicense = true;
        } else if (licenseData[0x24e2] == 'L') {
            // looks like an iso file itself
            for (unsigned i = 0; i < 16; i++) {
                memcpy(sector, licenseData + 2352 * i, 2352);
                makeHeaderOnce(sector);
                writeSector();
            }
            wroteLicense = true;
        } else {
            fmt::print("Unrecognized LICENSE file format {}\n", output.value());
        }
    }
    if (!wroteLicense) {
        memset(sector, 0, sizeof(sector));
        makeHeaderOnce(sector);
        for (unsigned i = 0; i < 16; i++) {
            writeSector();
        }
    }
    // The actual structure of the iso. We're only generating 3 sectors,
    // from 16 to 18, as it's the only things necessary for the PS1 bios.
    for (unsigned i = 0; i < 3; i++) {
        memset(sector, 0, sizeof(sector));
        makeHeaderOnce(sector);
        // This function will fill the sector with the right data, as
        // necessary for the PS1 bios.
        getSectorMinimal(sector + 24, LBA, exeSize, exeOffset);
        writeSector();
    }
    // Potential padding before the start of the exe.
    memset(sector, 0, sizeof(sector));
    makeHeaderOnce(sector);
    for (unsigned i = 0; i < offset; i++) {
        writeSector();
    }
    // The actual exe.
    for (unsigned i = 0; i < exeSize; i += 2048) {
        file->read(sector + 24, 2048);
        writeSector();
    }
    if (dataFile && !dataFile->failed()) {
        // The additional data file.
        unsigned sectors = (dataFile->size() + 2047) / 2048;
        for (unsigned i = 0; i < sectors; i++) {
            dataFile->read(sector + 24, 2048);
            writeSector();
        }
    }
    memset(sector, 0, sizeof(sector));
    makeHeaderOnce(sector);
    if (pad) {
        // 150 sectors padding.
        for (unsigned i = 0; i < 150; i++) {
            writeSector();
        }
    }
    fmt::print("Done.");
}
