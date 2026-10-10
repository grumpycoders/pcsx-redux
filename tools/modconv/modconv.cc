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
#include <numeric>
#include <string_view>
#include <vector>

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

namespace {

// How a MOD sample is laid out in SPU memory. Lengths are in bytes of the MOD sample, which are also
// samples, since MOD samples are 8 bits.
//
// One-shot samples skip the first word: ProTracker clears it on load, and uses it as the idle loop once a
// non-looped sample is done playing, so it is silence and not part of the sound. The trailing silent loop
// block plays that role on the SPU.
//
// The SPU can only loop on whole 28-sample blocks, so looped samples are laid out as:
//   [pad zeros][sample start .. loop start][loop body] x unroll
// - front zeros are padded so that the loop start lands exactly on a block boundary;
// - the loop body is unrolled the smallest number of times so that it ends on a block boundary,
//   which keeps the SPU loop period at exactly loopLength * unroll samples;
// - anything after the loop end is never heard on a MOD player, so it is dropped.
// The first word is skipped like for one-shot samples, unless the loop starts at word 0, in which case
// it is part of the loop body and has to be kept.
// The loop fields written to the .hit file are the clamped loop, 0 and 1 for one-shot samples. modplayer
// derives skip and pad from them with the same formulas to compute 9xx sample offsets, so they are part
// of the .hit contract.
struct SampleLayout {
    bool hasLoop = false;
    unsigned loopStart = 0;   // bytes
    unsigned loopLength = 0;  // bytes, one MOD loop period
    unsigned skip = 2;
    unsigned pad = 0;
    unsigned unroll = 1;
    unsigned body = 0;  // bytes of loop body written out
    bool exact = true;
    unsigned encodedLength = 0;
};

SampleLayout computeLayout(unsigned length, unsigned loopStart, unsigned loopLength, bool allowUnroll) {
    SampleLayout l;
    // MOD loop fields are in words. A repeat length of 0 or 1 word means "no loop"; a loop starting
    // at word 0 is a regular loop, usually over the whole sample.
    l.hasLoop = loopLength > 1;
    // Some trackers write loops running past the end of the sample; clamp them to the sample end.
    if (l.hasLoop && (loopStart >= length)) l.hasLoop = false;
    if (l.hasLoop && ((loopStart + loopLength) > length)) {
        loopLength = length - loopStart;
        l.hasLoop = loopLength > 1;
    }
    if (length == 0) return l;
    if (!l.hasLoop) {
        l.encodedLength = ((length - 1) * 2 + 27) / 28 * 16 + 16;
        return l;
    }
    l.loopStart = loopStart * 2;
    l.loopLength = loopLength * 2;
    l.skip = loopStart == 0 ? 0 : 2;
    l.pad = (28 - (l.loopStart - l.skip) % 28) % 28;
    const unsigned preLoop = l.pad + l.loopStart - l.skip;
    l.unroll = 28 / std::gcd(l.loopLength, 28u);
    l.body = l.loopLength * l.unroll;
    if (!allowUnroll || ((preLoop + l.body) / 28 * 16 >= 65536)) {
        // Unrolling is disabled or would overflow the 16 bits length field. Fall back to a single loop
        // period rounded to the nearest whole block; the loop period is then off by at most 14 samples.
        l.unroll = 1;
        l.body = std::max(28u, (l.loopLength + 14) / 28 * 28);
        l.exact = l.body == l.loopLength;
    }
    l.encodedLength = (preLoop + l.body) / 28 * 16;
    return l;
}

}  // namespace

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
            ? static_cast<PCSX::File*>(new PCSX::PosixFile(samplesFile.value().c_str(), PCSX::FileOps::TRUNCATE))
            : static_cast<PCSX::File*>(new PCSX::BufferFile(PCSX::FileOps::READWRITE));

    constexpr uint8_t silentLoopBlock[16] = {0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    constexpr unsigned spuMemory = 512 * 1024 - 0x1010;

    // Exact loops need unrolling, which can use a lot more SPU memory. If the exact layout doesn't fit,
    // disable unrolling for the whole module, which rounds loop periods to whole blocks instead.
    bool allowUnroll = true;
    {
        unsigned exactLength = 0;
        for (unsigned i = 0; i < 31; i++) {
            auto& sample = modFile.get<ModSamples>()[i];
            exactLength += computeLayout(sample.get<SampleLength>().value, sample.get<SampleLoopStart>().value,
                                         sample.get<SampleLoopLength>().value, true)
                               .encodedLength;
        }
        if (exactLength >= spuMemory) {
            fmt::print("Exact loops would need {} bytes of SPU memory; rounding loops to whole blocks instead.\n",
                       exactLength);
            allowUnroll = false;
        }
    }

    std::unique_ptr<PCSX::ADPCM::Encoder> encoder(new PCSX::ADPCM::Encoder);
    for (unsigned i = 0; i < 31; i++) {
        encoder->reset();
        auto& sample = modFile.get<ModSamples>()[i];
        fmt::print("Sample {:2} [{:22}] - ", i + 1, sample.get<SampleName>().value);
        auto length = sample.get<SampleLength>().value;
        const auto layout = computeLayout(length, sample.get<SampleLoopStart>().value,
                                          sample.get<SampleLoopLength>().value, allowUnroll);
        if (length == 0) {
            fmt::print("Empty\n");
            continue;
        }
        int16_t input[28];
        uint8_t spuBlock[16];
        unsigned encodedLength = 0;
        if (!layout.hasLoop) {
            file->skip<uint16_t>();
            length--;
            length *= 2;
            while (length >= 28) {
                for (unsigned j = 0; j < 28; j++) {
                    input[j] = int16_t(file->read<int8_t>()) * amplification;
                }
                length -= 28;
                encoder->processSPUBlock(input, spuBlock, PCSX::ADPCM::Encoder::BlockAttribute::OneShot);
                spuBlock[1] = length == 0 ? 1 : 0;
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
                spuBlock[1] = 0;
                encodedSamples->write(spuBlock, 16);
                encodedLength += 16;
            }
            encodedSamples->write(silentLoopBlock, 16);
            encodedLength += 16;
            fmt::print("Size {} -> {}\n", sample.get<SampleLength>().value * 2 - 2, encodedLength);
        } else {
            std::vector<int16_t> source(length * 2);
            for (auto& s : source) s = int16_t(file->read<int8_t>()) * amplification;
            std::vector<int16_t> pcm(layout.pad, 0);
            pcm.insert(pcm.end(), source.begin() + layout.skip, source.begin() + layout.loopStart);
            const unsigned loopBlock = pcm.size() / 28;
            for (unsigned j = 0; j < layout.body; j++) {
                pcm.push_back(source[layout.loopStart + j % layout.loopLength]);
            }
            const unsigned blocks = pcm.size() / 28;
            for (unsigned b = 0; b < blocks; b++) {
                // The loop start block is forced to filter 0, so it decodes the same whether the SPU
                // reaches it from the previous block or jumps to it from the loop end.
                encoder->processSPUBlock(pcm.data() + b * 28, spuBlock, PCSX::ADPCM::Encoder::BlockAttribute::OneShot,
                                         b == loopBlock);
                uint8_t blockAttribute = 0;
                if (b >= loopBlock) blockAttribute |= 2;
                if (b == loopBlock) blockAttribute |= 4;
                if (b == (blocks - 1)) blockAttribute |= 1;
                spuBlock[1] = blockAttribute;
                encodedSamples->write(spuBlock, 16);
                encodedLength += 16;
            }
            fmt::print("Size {} -> {}, loop {}+{} bytes, pad {}, unroll {}{}\n", sample.get<SampleLength>().value * 2,
                       encodedLength, layout.loopStart, layout.loopLength, layout.pad, layout.unroll,
                       layout.exact ? "" : ", loop period rounded to a whole block");
        }
        sample.get<SampleLength>().value = encodedLength;
        // Write back the loop that was actually encoded, after clamping, so that the player's 9xx
        // offsets wrap against the same loop.
        sample.get<SampleLoopStart>().value = layout.hasLoop ? layout.loopStart / 2 : 0;
        sample.get<SampleLoopLength>().value = layout.hasLoop ? layout.loopLength / 2 : 1;
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
