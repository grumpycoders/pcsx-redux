/***************************************************************************
 *   Copyright (C) 2024 PCSX-Redux authors                                 *
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

#include <algorithm>
#include <cctype>
#include <memory>
#include <string_view>

#include "flags.h"
#include "fmt/format.h"
#include "support/binstruct.h"
#include "support/file.h"
#include "support/typestring-wrapper.h"
#include "supportpsx/adpcm.h"

typedef PCSX::BinStruct::Field<PCSX::BinStruct::CString<20>, TYPESTRING("Title")> ModTitle;

typedef PCSX::BinStruct::Field<PCSX::BinStruct::CString<22>, TYPESTRING("Name")> SampleName;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::BEUInt16, TYPESTRING("Length")> SampleLength;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt8, TYPESTRING("FineTune")> SampleFineTune;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt8, TYPESTRING("Volume")> SampleVolume;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::BEUInt16, TYPESTRING("LoopStart")> SampleLoopStart;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::BEUInt16, TYPESTRING("LoopLength")> SampleLoopLength;

typedef PCSX::BinStruct::Struct<TYPESTRING("ModSample"), SampleName, SampleLength, SampleFineTune, SampleVolume,
                                SampleLoopStart, SampleLoopLength>
    ModSample;
typedef PCSX::BinStruct::RepeatedStruct<ModSample, TYPESTRING("ModSamples"), 31> ModSamples;

typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt8, TYPESTRING("Positions")> Positions;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt8, TYPESTRING("RestartPosition")> RestartPosition;
typedef PCSX::BinStruct::RepeatedField<PCSX::BinStruct::UInt8, TYPESTRING("PatternTable"), 128> PatternTable;

typedef PCSX::BinStruct::Field<PCSX::BinStruct::CString<4>, TYPESTRING("Signature")> Signature;

typedef PCSX::BinStruct::Struct<TYPESTRING("ModFile"), ModTitle, ModSamples, Positions, RestartPosition, PatternTable,
                                Signature>
    ModFile;

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    const auto output = args.get<std::string>("o");

    fmt::print(R"(
modconv by Nicolas "Pixel" Noble
https://github.com/grumpycoders/pcsx-redux/tree/main/tools/modconv/

)");

    const auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool hasOutput = output.has_value();
    const bool oneInput = inputs.size() == 1;
    const auto samplesFile = args.get<std::string>("s");
    const auto amplification = args.get<unsigned>("a").value_or(175);
    if (asksForHelp || !oneInput || !hasOutput) {
        fmt::print(R"(
Usage: {} input.mod [-h] [-s output.smp] [-a amp] -o output.hit
  input.mod         mandatory: specify the input mod file
  -o output.hit     mandatory: name of the output hit file.
  -h                displays this help information and exit.
  -s output.smp     optional: name of the output sample file.
  -a amplification  optional: value of sample amplification. Defaults to 175.

If the -s option is specified, the .hit file will only contain the pattern data,
and the .smp file will contain the sample data which can be loaded into the SPU
memory separately. If the -s option is not specified, the .hit file will contain
both the pattern and sample data.
)",
                   argv[0]);
        return -1;
    }

    const auto& input = inputs[0];
    PCSX::IO<PCSX::File> file(new PCSX::PosixFile(input));
    if (file->failed()) {
        fmt::print("Unable to open file: {}\n", input);
        return -1;
    }

    ModFile modFile;
    modFile.deserialize(file);

    std::string_view signature(modFile.get<Signature>().value, 4);

    unsigned channels = 0;
    if (signature == "M.K." || signature == "M!K!") {
        channels = 4;
    } else if (std::isdigit(signature[0]) && (signature[1] == 'C') && (signature[2] == 'H') && (signature[3] == 'N')) {
        channels = signature[0] - '0';
    } else if (std::isdigit(signature[0]) && std::isdigit(signature[1]) && (signature[2] == 'C') &&
               (signature[3] == 'H')) {
        channels = (signature[0] - '0') * 10 + signature[1] - '0';
    }

    if (channels == 0) {
        fmt::print("{} doesn't have a recognized MOD file format.\n", input);
        return -1;
    }

    if (channels > 24) {
        fmt::print("{} has too many channels ({}). The maximum is 24.\n", input, channels);
        return -1;
    }

    unsigned maxPatternID = 0;
    for (unsigned i = 0; i < 128; i++) {
        maxPatternID = std::max(maxPatternID, unsigned(modFile.get<PatternTable>()[i]));
    }

    auto patternData = file->read(channels * (maxPatternID + 1) * 256);

    fmt::print("Title:     {}\n", modFile.get<ModTitle>().value);
    fmt::print("Channels:  {}\n", channels);
    fmt::print("Positions: {}\n", modFile.get<Positions>().value);
    fmt::print("Patterns:  {}\n", maxPatternID + 1);
    fmt::print("Converting samples...\n");

    PCSX::IO<PCSX::File> encodedSamples =
        samplesFile.has_value()
            ? reinterpret_cast<PCSX::File*>(new PCSX::PosixFile(samplesFile.value().c_str(), PCSX::FileOps::TRUNCATE))
            : reinterpret_cast<PCSX::File*>(new PCSX::BufferFile(PCSX::FileOps::READWRITE));

    constexpr uint8_t silentLoopBlock[16] = {0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    std::unique_ptr<PCSX::ADPCM::Encoder> encoder(new PCSX::ADPCM::Encoder);
    for (unsigned i = 0; i < 31; i++) {
        encoder->reset();
        auto& sample = modFile.get<ModSamples>()[i];
        fmt::print("Sample {:2} [{:22}] - ", i + 1, sample.get<SampleName>().value);
        auto length = sample.get<SampleLength>().value;
        auto loopStart = sample.get<SampleLoopStart>().value;
        auto loopLength = sample.get<SampleLoopLength>().value;
        bool hasLoop = (loopStart > 0) && (loopLength > 1);
        if (length == 0) {
            fmt::print("Empty\n");
            continue;
        }
        int16_t input[28];
        uint8_t spuBlock[16];
        file->skip<uint16_t>();
        length--;
        length *= 2;
        unsigned position = 2;
        loopStart *= 2;
        unsigned loopEnd = loopStart + loopLength * 2;
        unsigned encodedLength = 0;
        while (length >= 28) {
            for (unsigned j = 0; j < 28; j++) {
                input[j] = int16_t(file->read<int8_t>()) * amplification;
            }
            length -= 28;
            encoder->processSPUBlock(input, spuBlock, PCSX::ADPCM::Encoder::BlockAttribute::OneShot);
            uint8_t blockAttribute = 0;
            if (length == 0) {
                blockAttribute |= 1;
            }
            if (hasLoop && (loopStart <= position)) {
                blockAttribute |= 2;
                if (position < (loopStart + 28)) {
                    blockAttribute |= 4;
                }
            }
            spuBlock[1] = blockAttribute;
            position += 28;
            encodedSamples->write(spuBlock, 16);
            encodedLength += 16;
        }
        if (length != 0) {
            for (unsigned j = 0; j < length; j++) {
                input[j] = int16_t(file->read<int8_t>()) * amplification;
            }
            for (unsigned j = length; j < 28; j++) {
                input[j] = 0;
            }
            encoder->processSPUBlock(input, spuBlock, PCSX::ADPCM::Encoder::BlockAttribute::OneShot);
            uint8_t blockAttribute = 0;
            if (hasLoop) {
                blockAttribute = 3;
                if (position < (loopStart + 28)) {
                    blockAttribute |= 4;
                }
            }
            spuBlock[1] = blockAttribute;
            position += 28;
            encodedSamples->write(spuBlock, 16);
            encodedLength += 16;
        }
        if (!hasLoop) {
            encodedSamples->write(silentLoopBlock, 16);
            encodedLength += 16;
        }
        fmt::print("Size {} -> {}\n", sample.get<SampleLength>().value * 2 - 2, encodedLength);
        sample.get<SampleLength>().value = encodedLength;
        if (encodedLength >= 65536) {
            fmt::print("Sample too big.\n");
            return -1;
        }
    }

    if (channels >= 10) {
        modFile.get<Signature>().value[0] = 'H';
        modFile.get<Signature>().value[1] = 'M';
        modFile.get<Signature>().value[2] = (channels / 10) + '0';
        modFile.get<Signature>().value[3] = (channels % 10) + '0';
    } else {
        modFile.get<Signature>().value[0] = 'H';
        modFile.get<Signature>().value[1] = 'I';
        modFile.get<Signature>().value[2] = 'T';
        modFile.get<Signature>().value[3] = channels + '0';
    }

    unsigned fullLength = 0;
    for (unsigned i = 0; i < 31; i++) {
        auto& sample = modFile.get<ModSamples>()[i];
        fullLength += sample.get<SampleLength>().value;
    }

    constexpr unsigned spuMemory = 512 * 1024 - 0x1010;

    if (fullLength >= spuMemory) {
        fmt::print("Not enough SPU memory to store all samples; {} bytes required but only {} available.\n", fullLength,
                   spuMemory);
        return -1;
    } else {
        fmt::print("Used {} bytes of SPU memory, {} still available.\n", fullLength, spuMemory - fullLength);
    }

    PCSX::IO<PCSX::File> out(new PCSX::PosixFile(output.value().c_str(), PCSX::FileOps::TRUNCATE));
    modFile.serialize(out);
    out->write(std::move(patternData));
    if (!samplesFile.has_value()) {
        out->write(std::move(encodedSamples.asA<PCSX::BufferFile>()->borrow()));
    }

    out->close();
    encodedSamples->close();
    if (samplesFile.has_value()) {
        fmt::print("All done, files {} and {} written out.\n", output.value(), args.get<std::string>("s").value());
    } else {
        fmt::print("All done, file {} written out.\n", output.value());
    }

    return 0;
}
