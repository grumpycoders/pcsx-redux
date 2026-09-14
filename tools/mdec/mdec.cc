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

// mdec - tooling for the PlayStation's Macroblock Decoder.
//
// ---------------------------------------------------------------------------
// CLI CONTRACT. Read this before adding a command.
//
// Usage is always:   mdec <command> [options]
//
//   1. The command is the FIRST POSITIONAL argument, always, and never a flag.
//      There is no default command: `mdec` with no command prints usage and
//      exits non-zero. This is what lets commands be added without any existing
//      invocation changing meaning.
//   2. `-i` is the input and `-o` is the output in EVERY command that has them.
//      An option name never means two different things in two commands.
//   3. Options are scoped to their command. A command ignores nothing silently:
//      an option it does not know is an error, not a no-op, because a silently
//      ignored option is how a user ends up believing a table was applied.
//   4. `mdec -h` lists commands. `mdec <command> -h` describes one command.
//   5. An unknown command lists what exists and exits non-zero. It never falls
//      back to a default.
//
// Commands so far: rawencode, rawdecode. "raw" means the MDEC's own run-level
// halfword stream, the bytes DMA0 consumes, with no BS/VLC entropy layer and no
// STR framing. When those land they get their own commands rather than flags on
// these, so that `rawencode` keeps meaning exactly what it means today.
// ---------------------------------------------------------------------------

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "flags.h"
#include "fmt/format.h"
#include "json.hpp"
#include "supportpsx/dct.h"

#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb/stb_image.h"
#include "stb/stb_image_write.h"

namespace {

// psx-spx zigzag: zscan[k] is the natural-order index of zigzag position k.
constexpr int c_zscan[64] = {
    0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,  12, 19, 26, 33, 40, 48,
    41, 34, 27, 20, 13, 6,  7,  14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23,
    30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
};

// The scale matrix every game uploads via MDEC(3), Q14. This is the INVERSE
// transform; the forward one used for encoding is DCT::standardBasis().
constexpr int16_t c_standardScale[64] = {
    0x5A82, 0x5A82, 0x5A82, 0x5A82, 0x5A82,         0x5A82,         0x5A82,         0x5A82,
    0x7D8A, 0x6A6D, 0x471C, 0x18F8, (int16_t)0xE707, (int16_t)0xB8E3, (int16_t)0x9592, (int16_t)0x8275,
    0x7641, 0x30FB, (int16_t)0xCF04, (int16_t)0x89BE, (int16_t)0x89BE, (int16_t)0xCF04, 0x30FB, 0x7641,
    0x6A6D, (int16_t)0xE707, (int16_t)0x8275, (int16_t)0xB8E3, 0x471C, 0x7D8A, 0x18F8, (int16_t)0x9592,
    0x5A82, (int16_t)0xA57D, (int16_t)0xA57D, 0x5A82, 0x5A82, (int16_t)0xA57D, (int16_t)0xA57D, 0x5A82,
    0x471C, (int16_t)0x8275, 0x18F8, 0x6A6D, (int16_t)0x9592, (int16_t)0xE707, 0x7D8A, (int16_t)0xB8E3,
    0x30FB, (int16_t)0x89BE, 0x7641, (int16_t)0xCF04, (int16_t)0xCF04, 0x7641, (int16_t)0x89BE, 0x30FB,
    0x18F8, (int16_t)0xB8E3, 0x6A6D, (int16_t)0x8275, 0x7D8A, (int16_t)0x9592, 0x471C, (int16_t)0xE707,
};

// The standard MDEC quantization table, the one psxavenc and the shipping
// encoders use. It is the DEFAULT here rather than an all-ones table: an
// unquantized DC for a bright 8x8 block lands around 1150, and the run-level
// field is signed TEN BITS. An identity quant table therefore clips the DC of
// any block brighter than about mid-grey, which is not a tuning problem, it is
// the reason the format carries a quant table at all.
constexpr uint8_t c_standardQuant[64] = {
    2,  16, 19, 22, 26, 27, 29, 34, 16, 16, 22, 24, 27, 29, 34, 37, 19, 22, 26, 27, 29, 34,
    34, 38, 22, 22, 26, 27, 29, 34, 37, 40, 22, 26, 27, 29, 32, 35, 40, 48, 26, 27, 29, 32,
    35, 40, 48, 58, 26, 27, 29, 34, 38, 46, 56, 69, 27, 29, 35, 38, 46, 56, 69, 83,
};

struct Tables {
    uint8_t quantY[64];
    uint8_t quantUV[64];
    int16_t scale[64];          // Q14 inverse matrix, what MDEC(3) receives
    PCSX::DCT::Basis forward;   // Q14 forward matrix, used by rawencode
    bool scaleFromFile = false;
    bool forwardFromFile = false;

    Tables() {
        memcpy(quantY, c_standardQuant, sizeof(quantY));
        memcpy(quantUV, c_standardQuant, sizeof(quantUV));
        memcpy(scale, c_standardScale, sizeof(scale));
        forward = PCSX::DCT::standardBasis();
    }
};

bool loadArray(const nlohmann::json &j, const char *key, int *out, unsigned n, std::string &err) {
    if (!j.contains(key)) return false;
    const auto &a = j[key];
    if (!a.is_array() || a.size() != n) {
        err = fmt::format("'{}' must be an array of {} numbers", key, n);
        return false;
    }
    for (unsigned i = 0; i < n; i++) {
        if (!a[i].is_number_integer()) {
            err = fmt::format("'{}'[{}] is not an integer", key, i);
            return false;
        }
        out[i] = a[i].get<int>();
    }
    return true;
}

// Table file layout:
//   { "quant": { "y": [64], "uv": [64] }, "scale": [64], "forward": [64] }
// Every member is optional; whatever is absent keeps its default.
bool loadTables(const std::string &path, Tables &t, std::string &err) {
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) {
        err = fmt::format("cannot open {}", path);
        return false;
    }
    std::string text;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
    fclose(f);

    auto j = nlohmann::json::parse(text, nullptr, false, true);
    if (j.is_discarded() || !j.is_object()) {
        err = fmt::format("{} is not a JSON object", path);
        return false;
    }
    int tmp[64];
    if (j.contains("quant") && j["quant"].is_object()) {
        if (loadArray(j["quant"], "y", tmp, 64, err)) {
            for (int i = 0; i < 64; i++) t.quantY[i] = static_cast<uint8_t>(std::clamp(tmp[i], 0, 255));
        } else if (!err.empty()) {
            return false;
        }
        if (loadArray(j["quant"], "uv", tmp, 64, err)) {
            for (int i = 0; i < 64; i++) t.quantUV[i] = static_cast<uint8_t>(std::clamp(tmp[i], 0, 255));
        } else if (!err.empty()) {
            return false;
        }
    }
    if (loadArray(j, "scale", tmp, 64, err)) {
        for (int i = 0; i < 64; i++) t.scale[i] = static_cast<int16_t>(tmp[i]);
        t.scaleFromFile = true;
    } else if (!err.empty()) {
        return false;
    }
    if (loadArray(j, "forward", tmp, 64, err)) {
        for (int i = 0; i < 64; i++) t.forward[i] = static_cast<int16_t>(tmp[i]);
        t.forwardFromFile = true;
    } else if (!err.empty()) {
        return false;
    }
    return true;
}

}  // namespace


namespace {

void printUsage(const char *argv0) {
    fmt::print(R"(
Usage: {} <command> [options]

  The command is always the first argument. Run `{} <command> -h` for its
  options. Adding a command never changes what an existing one does.

commands:
  rawencode   a PNG into a raw MDEC run-level stream (what DMA0 consumes)
  rawdecode   a raw MDEC run-level stream back into a PNG

  -h          this help, or a command's help when given after a command
)",
               argv0, argv0);
}

void usageRawEncode() {
    fmt::print(R"(
Usage: mdec rawencode -i input.png -o output.bin [options]

  -i file     mandatory: input PNG. Dimensions are rounded UP to a multiple of
              16 by edge replication; the padding is encoded and reported.
  -o file     mandatory: raw MDEC run-level stream, little endian halfwords.
  -t file     optional: JSON tables, see below.
  -q n        optional: quantizer scale, 1..63. Default 8.
  -transform  optional: exact | fast | symmetric. Default exact.
              exact     general basis, int32 accumulation, reference accurate
              fast      general basis, Q15 narrowing, quicker and coarser
              symmetric general basis with the even/odd butterfly; needs a basis
                        with the usual symmetry and refuses one without it

JSON tables, every member optional, absent members keep their defaults:
  {{ "quant": {{ "y": [64 ints], "uv": [64 ints] }},
     "scale": [64 ints], "forward": [64 ints] }}

  "forward" is the Q14 matrix this command transforms with. "scale" is the Q14
  matrix MDEC(3) receives, used by rawdecode. They are the two halves of a pair
  and THIS TOOL DOES NOT DERIVE ONE FROM THE OTHER: supply "scale" alone and
  encoding still uses the default forward basis, which is almost certainly not
  what you want. It says so when you do.

  The default quant table is the standard one every shipping encoder uses. An
  all-ones table looks appealing because it makes dequantization the identity,
  but the run-level DC field is signed TEN BITS and an unquantized DC runs to
  about 1150, so identity quant clips every block brighter than mid-grey.
)");
}

void usageRawDecode() {
    fmt::print(R"(
Usage: mdec rawdecode -i input.bin -o output.png -width W -height H [options]

  -i file     mandatory: raw MDEC run-level stream.
  -o file     mandatory: output PNG.
  -width n    mandatory: width in pixels, multiple of 16.
  -height n   mandatory: height in pixels, multiple of 16.
  -t file     optional: JSON tables. Only "quant" and "scale" are used here.

  The stream carries no dimensions, which is why they are mandatory rather than
  guessed. This decodes with psx-spx's real_idct_core against "scale", so a
  custom matrix is honoured exactly as the hardware honours it.
)");
}

int clamp10(int v, unsigned &clipped) {
    if (v > 511) {
        clipped++;
        return 511;
    }
    if (v < -512) {
        clipped++;
        return -512;
    }
    return v;
}

int divRound(int num, int den) {
    if (den == 0) return 0;
    return (num < 0) ? -((-num + den / 2) / den) : ((num + den / 2) / den);
}

// psx-spx real_idct_core, verified against real consoles 2026-09-14 to within
// 3 LSB on a custom matrix.
void realIdct(int *block, const int16_t *scale) {
    int temp[64];
    int *src = block;
    int *dst = temp;
    for (int pass = 0; pass < 2; pass++) {
        for (int x = 0; x < 8; x++) {
            for (int y = 0; y < 8; y++) {
                int64_t sum = 0;
                for (int z = 0; z < 8; z++) sum += static_cast<int64_t>(src[y + z * 8]) * (scale[x + z * 8] / 8);
                dst[x + y * 8] = static_cast<int>((sum + 0xfff) >> 13);
            }
        }
        std::swap(src, dst);
    }
    if (src != block) memcpy(block, src, sizeof(temp));
}

int cmdRawEncode(CommandLine::args &args, bool asksForHelp) {
    if (asksForHelp) {
        usageRawEncode();
        return 0;
    }
    const auto in = args.get<std::string>("i");
    const auto out = args.get<std::string>("o");
    if (!in.has_value() || !out.has_value()) {
        usageRawEncode();
        return -1;
    }
    const int qscale = std::clamp(args.get<int>("q").value_or(8), 1, 63);
    const std::string which = args.get<std::string>("transform").value_or("exact");

    PCSX::DCT::Transform transform;
    if (which == "exact") {
        transform = PCSX::DCT::Transform::ExactMatrix;
    } else if (which == "fast") {
        transform = PCSX::DCT::Transform::FastMatrix;
    } else if (which == "symmetric") {
        transform = PCSX::DCT::Transform::FastSymmetric;
    } else {
        fmt::print(stderr, "Unknown -transform '{}'; expected exact, fast or symmetric.\n", which);
        return -1;
    }

    Tables tables;
    if (auto t = args.get<std::string>("t"); t.has_value()) {
        std::string err;
        if (!loadTables(t.value(), tables, err)) {
            fmt::print(stderr, "{}\n", err.empty() ? "cannot read tables" : err);
            return -1;
        }
        if (tables.scaleFromFile && !tables.forwardFromFile) {
            fmt::print(stderr,
                       "warning: {} supplies \"scale\" but no \"forward\". Encoding with the DEFAULT forward\n"
                       "         basis, which does not match that scale matrix. Supply \"forward\" too.\n",
                       t.value());
        }
    }

    int w = 0, h = 0, comp = 0;
    uint8_t *pixels = stbi_load(in.value().c_str(), &w, &h, &comp, 3);
    if (!pixels) {
        fmt::print(stderr, "cannot read {}: {}\n", in.value(), stbi_failure_reason());
        return -1;
    }
    const int pw = (w + 15) & ~15;
    const int ph = (h + 15) & ~15;

    std::vector<uint8_t> y(static_cast<size_t>(pw) * ph);
    std::vector<uint8_t> cb(static_cast<size_t>(pw / 2) * (ph / 2));
    std::vector<uint8_t> cr(cb.size());
    // Full range JPEG YCbCr, which is what the MDEC's colour conversion inverts.
    auto at = [&](int x, int yy, int c) {
        const int sx = std::min(x, w - 1), sy = std::min(yy, h - 1);
        return static_cast<int>(pixels[(static_cast<size_t>(sy) * w + sx) * 3 + c]);
    };
    for (int j = 0; j < ph; j++) {
        for (int i = 0; i < pw; i++) {
            const int r = at(i, j, 0), g = at(i, j, 1), b = at(i, j, 2);
            y[static_cast<size_t>(j) * pw + i] =
                static_cast<uint8_t>(std::clamp((299 * r + 587 * g + 114 * b) / 1000, 0, 255));
        }
    }
    for (int j = 0; j < ph / 2; j++) {
        for (int i = 0; i < pw / 2; i++) {
            int rs = 0, gs = 0, bs = 0;
            for (int dy = 0; dy < 2; dy++) {
                for (int dx = 0; dx < 2; dx++) {
                    rs += at(i * 2 + dx, j * 2 + dy, 0);
                    gs += at(i * 2 + dx, j * 2 + dy, 1);
                    bs += at(i * 2 + dx, j * 2 + dy, 2);
                }
            }
            const int r = rs / 4, g = gs / 4, b = bs / 4;
            const int luma = (299 * r + 587 * g + 114 * b) / 1000;
            const size_t o = static_cast<size_t>(j) * (pw / 2) + i;
            cb[o] = static_cast<uint8_t>(std::clamp(128 + (b - luma) * 564 / 1000, 0, 255));
            cr[o] = static_cast<uint8_t>(std::clamp(128 + (r - luma) * 713 / 1000, 0, 255));
        }
    }
    stbi_image_free(pixels);

    PCSX::DCT::Frame frame;
    frame.y = y.data();
    frame.cb = cb.data();
    frame.cr = cr.data();
    frame.width = pw;
    frame.height = ph;
    frame.yStride = pw;
    frame.cStride = pw / 2;

    std::vector<int16_t> coeffs(PCSX::DCT::requiredCoefficientCount(pw, ph));
    PCSX::DCT::Encoder encoder(0, transform, tables.forward);
    auto promise = encoder.submit(frame, coeffs);
    const auto result = promise.get();
    if (result.failed) {
        fmt::print(stderr, "the DCT stage refused the frame\n");
        return -1;
    }

    unsigned clipped = 0;
    std::vector<uint16_t> stream;
    stream.reserve(result.blockCount * 12);
    for (uint32_t b = 0; b < result.blockCount; b++) {
        const int16_t *blk = coeffs.data() + static_cast<size_t>(b) * 64;
        const uint8_t *qt = (b % 6) < 2 ? tables.quantUV : tables.quantY;
        const int dc = clamp10(divRound(blk[0], qt[0] ? qt[0] : 1), clipped);
        stream.push_back(static_cast<uint16_t>(((qscale & 0x3f) << 10) | (dc & 0x3ff)));
        int run = 0;
        for (int k = 1; k < 64; k++) {
            const int den = qt[k] * qscale;
            const int ac = clamp10(divRound(blk[c_zscan[k]] * 8, den ? den : 1), clipped);
            if (ac == 0) {
                run++;
                continue;
            }
            stream.push_back(static_cast<uint16_t>(((run & 0x3f) << 10) | (ac & 0x3ff)));
            run = 0;
        }
        stream.push_back(0xfe00);
    }
    // psx-spx: MDEC(1) parameters want padding to 40h halfwords so the DMA block
    // count is a whole number of 20h-word blocks. A half block hangs DMA0.
    while (stream.size() % 64) stream.push_back(0xfe00);

    FILE *f = fopen(out.value().c_str(), "wb");
    if (!f) {
        fmt::print(stderr, "cannot write {}\n", out.value());
        return -1;
    }
    for (uint16_t v : stream) {
        const uint8_t bytes[2] = {static_cast<uint8_t>(v & 0xff), static_cast<uint8_t>(v >> 8)};
        fwrite(bytes, 1, 2, f);
    }
    fclose(f);

    fmt::print("{}x{}", w, h);
    if (pw != w || ph != h) fmt::print(" padded to {}x{}", pw, ph);
    fmt::print(", {} blocks, {} halfwords, q_scale {}, transform {}\n", result.blockCount, stream.size(), qscale,
               which);
    if (clipped) {
        fmt::print(stderr, "warning: {} coefficients clipped to the 10 bit run-level range. Raise -q.\n", clipped);
    }
    return 0;
}

int cmdRawDecode(CommandLine::args &args, bool asksForHelp) {
    if (asksForHelp) {
        usageRawDecode();
        return 0;
    }
    const auto in = args.get<std::string>("i");
    const auto out = args.get<std::string>("o");
    const int w = args.get<int>("width").value_or(0);
    const int h = args.get<int>("height").value_or(0);
    if (!in.has_value() || !out.has_value() || w <= 0 || h <= 0 || (w % 16) || (h % 16)) {
        usageRawDecode();
        return -1;
    }

    Tables tables;
    if (auto t = args.get<std::string>("t"); t.has_value()) {
        std::string err;
        if (!loadTables(t.value(), tables, err)) {
            fmt::print(stderr, "{}\n", err.empty() ? "cannot read tables" : err);
            return -1;
        }
    }

    FILE *f = fopen(in.value().c_str(), "rb");
    if (!f) {
        fmt::print(stderr, "cannot open {}\n", in.value());
        return -1;
    }
    std::vector<uint16_t> stream;
    uint8_t bytes[2];
    while (fread(bytes, 1, 2, f) == 2) stream.push_back(static_cast<uint16_t>(bytes[0] | (bytes[1] << 8)));
    fclose(f);

    const int mbx = w / 16, mby = h / 16;
    std::vector<uint8_t> image(static_cast<size_t>(w) * h * 3);
    size_t pos = 0;
    for (int my = 0; my < mby; my++) {
        for (int mx = 0; mx < mbx; mx++) {
            int blocks[6][64];
            for (int b = 0; b < 6; b++) {
                memset(blocks[b], 0, sizeof(blocks[b]));
                if (pos >= stream.size()) {
                    fmt::print(stderr, "stream ran out at macroblock {},{} block {}\n", mx, my, b);
                    return -1;
                }
                const uint8_t *qt = b < 2 ? tables.quantUV : tables.quantY;
                uint16_t n = stream[pos++];
                const int qscale = (n >> 10) & 0x3f;
                auto sext10 = [](uint16_t v) { return static_cast<int>(static_cast<int16_t>(v << 6)) >> 6; };
                blocks[b][0] = std::clamp(sext10(n & 0x3ff) * qt[0], -0x400, 0x3ff);
                for (int k = 0;;) {
                    if (pos >= stream.size()) break;
                    n = stream[pos++];
                    if (n == 0xfe00) break;
                    k += ((n >> 10) & 0x3f) + 1;
                    if (k > 63) break;
                    blocks[b][c_zscan[k]] =
                        std::clamp((sext10(n & 0x3ff) * qt[k] * qscale + 4) / 8, -0x400, 0x3ff);
                }
                realIdct(blocks[b], tables.scale);
            }
            for (int py = 0; py < 16; py++) {
                for (int px = 0; px < 16; px++) {
                    const int cidx = (py / 2) * 8 + (px / 2);
                    const int cr = blocks[0][cidx], cb = blocks[1][cidx];
                    const int yblk = (py / 8) * 2 + (px / 8);
                    const int yv = blocks[2 + yblk][(py % 8) * 8 + (px % 8)];
                    const int r = yv + (1402 * cr) / 1000;
                    const int g = yv - (344 * cb + 714 * cr) / 1000;
                    const int bl = yv + (1772 * cb) / 1000;
                    const size_t o = (static_cast<size_t>(my * 16 + py) * w + (mx * 16 + px)) * 3;
                    image[o + 0] = static_cast<uint8_t>(std::clamp(r + 128, 0, 255));
                    image[o + 1] = static_cast<uint8_t>(std::clamp(g + 128, 0, 255));
                    image[o + 2] = static_cast<uint8_t>(std::clamp(bl + 128, 0, 255));
                }
            }
        }
    }
    if (!stbi_write_png(out.value().c_str(), w, h, 3, image.data(), w * 3)) {
        fmt::print(stderr, "cannot write {}\n", out.value());
        return -1;
    }
    fmt::print("{}x{}, {} macroblocks, {} halfwords consumed of {}\n", w, h, mbx * mby, pos, stream.size());
    return 0;
}

}  // namespace


int main(int argc, char **argv) {
    CommandLine::args args(argc, argv);
    const auto positional = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);

    if (positional.empty()) {
        printUsage(argv[0]);
        return asksForHelp ? 0 : -1;
    }
    const std::string command(positional[0]);

    if (command == "rawencode") return cmdRawEncode(args, asksForHelp);
    if (command == "rawdecode") return cmdRawDecode(args, asksForHelp);

    fmt::print(stderr, "Unknown command: {}\n\n", command);
    printUsage(argv[0]);
    return -1;
}
