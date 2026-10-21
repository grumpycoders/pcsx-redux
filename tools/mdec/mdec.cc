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
// Commands so far: rawencode, bsencode, rawdecode. "raw" means the MDEC's own
// run-level halfword stream, the bytes DMA0 consumes, with no BS/VLC entropy
// layer and no STR framing; `bsencode` is the same stream VLC coded into Sony's
// legacy BS. STR framing gets its own command when it lands, rather than a flag
// on either of these, so that each one keeps meaning what it means today.
// ---------------------------------------------------------------------------

#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <exception>
#include <filesystem>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include "args/args.hxx"
#include "fmt/format.h"
#include "json.hpp"
#include "support/tool-args.h"
#include "supportpsx/dct.h"
#include "core/mdec-decoder.h"

#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb/stb_image.h"
#include "stb/stb_image_write.h"

namespace {

struct Tables {
    uint8_t quantY[64];
    uint8_t quantUV[64];
    int16_t scale[64];          // Q14 inverse matrix, what MDEC(3) receives
    PCSX::DCT::Basis forward;   // Q14 forward matrix, used by rawencode
    bool scaleFromFile = false;
    bool forwardFromFile = false;

    Tables() {
        memcpy(quantY, PCSX::DCT::standardQuantTable(), sizeof(quantY));
        memcpy(quantUV, PCSX::DCT::standardQuantTable(), sizeof(quantUV));
        memcpy(scale, PCSX::MDECDecoder::standardScaleTable(), sizeof(scale));
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
    if (j.contains("quant") && !j["quant"].is_object()) {
        err = fmt::format("{}: \"quant\" must be an object with \"y\" and/or \"uv\" arrays", path);
        return false;
    }
    if (j.contains("quant")) {
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

// Every option of every command, so that the command can be found wherever it sits
// among them. main() then checks each command was only given its own (rule 3).
struct Options {
    args::ArgumentParser parser{""};
    args::ValueFlag<std::string> i{parser, "i", "", {"i"}};
    args::ValueFlag<std::string> o{parser, "o", "", {"o"}};
    args::ValueFlag<std::string> t{parser, "t", "", {"t"}};
    args::ValueFlag<int> q{parser, "q", "", {"q"}};
    args::ValueFlag<int> quality{parser, "quality", "", {"quality"}};
    args::ValueFlag<int> qscale{parser, "qscale", "", {"qscale"}};
    args::ValueFlag<std::string> order{parser, "order", "", {"order"}};
    args::ValueFlag<std::string> transform{parser, "transform", "", {"transform"}};
    args::ValueFlag<int> width{parser, "width", "", {"width"}};
    args::ValueFlag<int> height{parser, "height", "", {"height"}};
    args::Flag h{parser, "h", "", {"h"}};
    args::PositionalList<std::string> positional{parser, "command", ""};
};

void printUsage(const char *argv0) {
    fmt::print(R"(
Usage: {} <command> [options]

  The command is always the first argument. Run `{} <command> -h` for its
  options. Adding a command never changes what an existing one does.

commands:
  rawencode   a PNG into a raw MDEC run-level stream (what DMA0 consumes)
  bsencode    a PNG into Sony's legacy BS: the same stream, VLC/Huffman coded
  bsdecode    a BS stream back into a raw MDEC run-level stream
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
  -quality n  optional: 1..100, higher is better. Default 50, which is exactly
              the q_scale of 8 this defaulted to before there was a dial. The
              spread is geometric, because the format's rate curve is: 100 is
              q_scale 1, 50 is 8, 1 is 63.
  -qscale n   optional: the MDEC's own q_scale field, 1..63, for when you want to
              set the format value directly. Higher is coarser, so it reads the
              opposite way round to -quality. Mutually exclusive with it.

              Neither one touches the quant table, and that is deliberate. qt[0]
              is 2 and the DC divisor is qt[0]*2, so a finer table pins the DC
              divisor at 2 and DC coefficients overrun the signed 10 bit field -
              measured, on a smooth frame, mean error going 1.31 to 19.18 while
              the size barely moved. The standard table is the finest DC the
              format tolerates rather than a default to improve on. Supply a
              genuinely different table with -t if you want one.

  -order      optional: column | raster. Default column.
              column walks 16-pixel columns top to bottom, which is what retail
              STR does; it makes each column of the decoded output one
              contiguous run, so a player can upload a whole column as a single
              VRAM rect instead of one transfer per macroblock. raster walks the
              image row by row. The pixels are identical either way, only the
              order the macroblocks arrive in changes, and a decoder that
              disagrees with the stream about it renders bands of
              vertically-striped blocks.

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
  Quant arrays are in the order MDEC(2) receives them: zigzag, entry k being
  the divisor for coefficient k of the stream, not the raster position.
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
  -order      optional: column | raster. Default column, which is what retail
              STR frames use. Must match the order the stream was encoded in
              (rawencode -order).

  The stream carries no dimensions, which is why they are mandatory rather than
  guessed. This is the emulator's MDEC decoder, byte for byte: the standard
  matrix runs its AAN IDCT, any other "scale" runs psx-spx's real_idct_core, so
  a custom matrix is honoured the way the hardware honours it.
)");
}

// The -order spelling of a macroblock order. The default comes from
// PCSX::DCT::Frame, so the encoder and decoder cannot disagree about it.
const char *orderName(PCSX::DCT::MacroblockOrder order) {
    return order == PCSX::DCT::MacroblockOrder::Column ? "column" : "raster";
}

int cmdEncode(Options &opts, bool asksForHelp, PCSX::DCT::Container container) {
    if (asksForHelp) {
        usageRawEncode();
        return 0;
    }
    const auto in = PCSX::ToolArgs::get(opts.i);
    const auto out = PCSX::ToolArgs::get(opts.o);
    if (!in.has_value() || !out.has_value()) {
        usageRawEncode();
        return -1;
    }
    // -q is RETIRED rather than redefined. It used to mean the raw q_scale field,
    // and making it mean a quality percentage would silently invert its sense -
    // higher was worse, higher is now better - while every old invocation kept
    // working and produced a very different image. An unknown option is already an
    // error here, so the hard break is the one that cannot be misread.
    if (PCSX::ToolArgs::get(opts.q).has_value()) {
        fmt::print(stderr,
                   "-q is retired because it meant the raw q_scale field, which reads backwards as a quality "
                   "dial. Use -quality 1..100 (higher is better, 50 is the old default), or -qscale 1..63 for "
                   "the format field itself.\n");
        return -1;
    }
    const auto qualityOpt = PCSX::ToolArgs::get(opts.quality);
    const auto qscaleOpt = PCSX::ToolArgs::get(opts.qscale);
    if (qualityOpt.has_value() && qscaleOpt.has_value()) {
        fmt::print(stderr, "-quality and -qscale set the same thing. Pass one.\n");
        return -1;
    }
    const int quality = std::clamp(qualityOpt.value_or(50), 1, 100);
    const int qscale =
        qscaleOpt.has_value() ? std::clamp(qscaleOpt.value(), 1, 63) : PCSX::DCT::qualityToQScale(quality);
    const std::string which = PCSX::ToolArgs::get(opts.transform).value_or("exact");

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
    if (auto t = PCSX::ToolArgs::get(opts.t); t.has_value()) {
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

    // Frame's default order is column, the way retail STR walks macroblocks, so
    // each decoded column is one contiguous run and a player can upload it as a
    // single VRAM rect. -order raster is the explicit opt-out.
    const std::string order = PCSX::ToolArgs::get(opts.order).value_or(orderName(frame.order));
    if (order == "column") {
        frame.order = PCSX::DCT::MacroblockOrder::Column;
    } else if (order == "raster") {
        frame.order = PCSX::DCT::MacroblockOrder::Raster;
    } else {
        fmt::print(stderr, "-order takes raster or column, got '{}'.\n", order);
        return -1;
    }

    std::vector<int16_t> coeffs(PCSX::DCT::requiredCoefficientCount(pw, ph));
    PCSX::DCT::Encoder encoder(0, transform, tables.forward);
    auto promise = encoder.submit(frame, coeffs);
    const auto result = promise.get();
    if (result.failed) {
        fmt::print(stderr, "the DCT stage refused the frame\n");
        return -1;
    }

    // Quantization and run-level packing live in supportpsx/dct now: they are
    // format knowledge, not CLI knowledge, and putting them there is what lets a
    // caller drive per-macroblock rate control through a functor.
    std::vector<uint16_t> stream;
    stream.reserve(result.blockCount * 12);
    PCSX::DCT::QuantTables qtabs;
    qtabs.y = tables.quantY;
    qtabs.uv = tables.quantUV;
    const auto packed = PCSX::DCT::pack(coeffs, result, qtabs, qscale, stream);
    if (packed.failed) {
        fmt::print(stderr, "the packing stage refused the frame\n");
        return -1;
    }
    // Two counters, two remedies. Merging them is what made the old message
    // advise "raise -q" for a DC clip, which q_scale structurally cannot fix.
    const unsigned clipped = packed.clippedAc + packed.clippedDc;

    FILE *f = fopen(out.value().c_str(), "wb");
    if (!f) {
        fmt::print(stderr, "cannot write {}\n", out.value());
        return -1;
    }
    std::vector<uint8_t> wrapped;
    auto wrap = PCSX::DCT::toContainer(stream, container, wrapped);
    if (wrap.failed) {
        fclose(f);
        fmt::print(stderr, "cannot wrap the stream: {}\n", wrap.error);
        return -1;
    }
    const bool wrote = fwrite(wrapped.data(), 1, wrapped.size(), f) == wrapped.size();
    if ((fclose(f) != 0) || !wrote) {
        fmt::print(stderr, "error writing {}\n", out.value());
        return -1;
    }

    fmt::print("{}x{}", w, h);
    if (pw != w || ph != h) fmt::print(" padded to {}x{}", pw, ph);
    if (!qscaleOpt.has_value()) fmt::print(", quality {}", quality);
    fmt::print(", {} blocks, {} halfwords, q_scale {}, transform {}", result.blockCount, stream.size(), qscale,
               which);
    const double raw = static_cast<double>(stream.size() * 2);
    if (container == PCSX::DCT::Container::Bs) {
        fmt::print(", BS {} bytes ({:.1f}% of raw)", wrap.bytes, 100.0 * wrap.bytes / raw);
    }
    fmt::print("\n");
    if (clipped) {
        // Name the lever that can actually reach each one. q_scale is in the AC
        // divisor only, so it cannot fix a clipped DC however far it is raised.
        if (packed.clippedAc) {
            fmt::print(stderr, "warning: {} AC coefficients clipped to the 10 bit run-level range. Raise -qscale, or "
                       "lower -quality.\n",
                       packed.clippedAc);
        }
        if (packed.clippedDc) {
            fmt::print(stderr,
                       "warning: {} DC coefficients clipped to the 10 bit run-level range. Raising -qscale or "
                       "lowering -quality will NOT help - q_scale is not in the DC divisor. Use a coarser quant "
                       "table: raise quant[0] with -t.\n",
                       packed.clippedDc);
        }
    }
    return 0;
}

int cmdBsDecode(Options &opts, bool asksForHelp) {
    if (asksForHelp) {
        fmt::print(R"(
Usage: mdec bsdecode -i input.bs -o output.bin

  -i file     mandatory: a BS stream, as bsencode writes.
  -o file     mandatory: the raw MDEC run-level stream it carries.

  This undoes the VLC layer and nothing else, so it composes: `bsdecode` then
  `rawdecode` gets you back to a PNG, and `bsencode | bsdecode` must reproduce
  `rawencode` byte for byte on the same input and settings.

  Dimensions are not needed and not accepted - a BS header carries the decoded
  length, which is the whole reason its first word is the MDEC decode command.
)");
        return 0;
    }
    auto in = PCSX::ToolArgs::get(opts.i);
    auto out = PCSX::ToolArgs::get(opts.o);
    if (!in.has_value() || !out.has_value()) {
        fmt::print(stderr, "bsdecode needs -i and -o\n");
        return -1;
    }
    FILE *f = fopen(in.value().c_str(), "rb");
    if (!f) {
        fmt::print(stderr, "cannot read {}\n", in.value());
        return -1;
    }
    std::vector<uint8_t> bytes;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) bytes.insert(bytes.end(), buf, buf + n);
    fclose(f);

    std::vector<uint16_t> rl;
    auto r = PCSX::DCT::fromContainer(bytes, PCSX::DCT::Container::Bs, rl);
    if (r.failed) {
        fmt::print(stderr, "cannot decode {}: {}\n", in.value(), r.error);
        return -1;
    }
    FILE *o = fopen(out.value().c_str(), "wb");
    if (!o) {
        fmt::print(stderr, "cannot write {}\n", out.value());
        return -1;
    }
    bool wrote = true;
    for (uint16_t v : rl) {
        const uint8_t b2[2] = {static_cast<uint8_t>(v & 0xff), static_cast<uint8_t>(v >> 8)};
        if (fwrite(b2, 1, 2, o) != 2) {
            wrote = false;
            break;
        }
    }
    if ((fclose(o) != 0) || !wrote) {
        fmt::print(stderr, "error writing {}\n", out.value());
        return -1;
    }
    fmt::print("{} blocks, q_scale {}, {} halfwords ({} words as the header declares)\n", r.blocks, r.qScale,
               rl.size(), r.rlWords);
    return 0;
}

int cmdRawDecode(Options &opts, bool asksForHelp) {
    if (asksForHelp) {
        usageRawDecode();
        return 0;
    }
    const auto in = PCSX::ToolArgs::get(opts.i);
    const auto out = PCSX::ToolArgs::get(opts.o);
    const int w = PCSX::ToolArgs::get(opts.width).value_or(0);
    const int h = PCSX::ToolArgs::get(opts.height).value_or(0);
    if (!in.has_value() || !out.has_value() || w <= 0 || h <= 0 || (w % 16) || (h % 16)) {
        usageRawDecode();
        return -1;
    }
    const std::string order = PCSX::ToolArgs::get(opts.order).value_or(orderName(PCSX::DCT::Frame{}.order));
    if (order != "raster" && order != "column") {
        fmt::print(stderr, "-order takes raster or column, got '{}'.\n", order);
        return -1;
    }
    const bool column = order == "column";

    Tables tables;
    if (auto t = PCSX::ToolArgs::get(opts.t); t.has_value()) {
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
    // Kept as the bytes on disk: the decoder reads little-endian halfwords, as
    // they sit in guest memory.
    std::vector<uint16_t> stream;
    uint8_t bytes[2];
    while (fread(bytes, 1, 2, f) == 2) {
        uint16_t v;
        memcpy(&v, bytes, 2);
        stream.push_back(v);
    }
    fclose(f);

    // What MDEC(2) and MDEC(3) would leave in the chip, then the emulator's own
    // decode of the stream.
    PCSX::MDECDecoder::Tables chip;
    chip.setQuant(tables.quantY, tables.quantUV);
    chip.setScale(tables.scale);
    const int mbx = w / 16, mby = h / 16;
    std::vector<uint8_t> image(static_cast<size_t>(w) * h * 3);
    const auto frame = PCSX::MDECDecoder::decodeFrame(stream.data(), static_cast<unsigned>(stream.size()), chip, w, h,
                                                      column, image.data());
    const auto &st = frame.status;
    switch (st.anomaly) {
        case PCSX::MDECDecoder::Anomaly::None:
            break;
        case PCSX::MDECDecoder::Anomaly::Exhausted:
            if (st.atHeader) {
                fmt::print(stderr, "stream ran out at macroblock {},{} block {}\n", frame.mbX, frame.mbY, st.block);
            } else {
                fmt::print(stderr, "block at macroblock {},{} block {} has no 0xfe00 terminator\n", frame.mbX,
                           frame.mbY, st.block);
            }
            return -1;
        case PCSX::MDECDecoder::Anomaly::RunPast63:
            fmt::print(stderr, "block at macroblock {},{} block {} runs past coefficient 63\n", frame.mbX, frame.mbY,
                       st.block);
            return -1;
    }
    const size_t pos = frame.consumed;
    if (!stbi_write_png(out.value().c_str(), w, h, 3, image.data(), w * 3)) {
        fmt::print(stderr, "cannot write {}\n", out.value());
        return -1;
    }
    fmt::print("{}x{}, {} macroblocks, {} halfwords consumed of {}\n", w, h, mbx * mby, pos, stream.size());
    return 0;
}

}  // namespace


int main(int argc, char **argv) {
    Options opts;
    std::vector<std::string> unknown;
    PCSX::ToolArgs::parse(opts.parser, argc, argv, &unknown);
    const auto positional = args::get(opts.positional);
    const bool asksForHelp = args::get(opts.h);

    if (positional.empty()) {
        printUsage(argv[0]);
        return asksForHelp ? 0 : -1;
    }
    const std::string command(positional[0]);

    // DCT::Transform::FastSymmetric throws std::invalid_argument on a basis
    // without the even/odd symmetry, which is a documented and reachable input
    // here - `-transform symmetric` with a `-t` table that lacks it. Without this
    // the exception escapes main and the tool SIGABRTs on an input its own -h text
    // says it refuses, while every other bad input prints a line and returns
    // non-zero. Measured with `-transform exact` on the same table as the control:
    // exit 0, encodes fine, so the abort was the symmetry check and not the table
    // loader.
    // Rule 3 of the contract at the top of this file.
    // The options given, in name order, whether some command knows them or not.
    std::vector<std::string> given = unknown;
    for (auto flag : opts.parser.GetAllFlags()) {
        if (flag->Matched()) given.push_back(flag->Name());
    }
    std::sort(given.begin(), given.end());
    auto knows = [&](std::initializer_list<std::string_view> known) {
        for (const auto &name : given) {
            if (name == "h") continue;
            if (std::find(known.begin(), known.end(), name) == known.end()) {
                fmt::print(stderr, "{}: unknown option -{}\n", command, name);
                return false;
            }
        }
        return true;
    };
    const std::initializer_list<std::string_view> encodeOptions = {"i",     "o",         "t",    "q",
                                                                    "quality", "qscale", "order", "transform"};

    try {
        if (command == "rawencode") {
            return knows(encodeOptions) ? cmdEncode(opts, asksForHelp, PCSX::DCT::Container::Raw) : -1;
        }
        if (command == "bsencode") {
            return knows(encodeOptions) ? cmdEncode(opts, asksForHelp, PCSX::DCT::Container::Bs) : -1;
        }
        if (command == "bsdecode") return knows({"i", "o"}) ? cmdBsDecode(opts, asksForHelp) : -1;
        if (command == "rawdecode") {
            return knows({"i", "o", "t", "width", "height", "order"}) ? cmdRawDecode(opts, asksForHelp) : -1;
        }
    } catch (const std::exception &e) {
        fmt::print(stderr, "{}: {}\n", command, e.what());
        return -1;
    }

    fmt::print(stderr, "Unknown command: {}\n\n", command);
    printUsage(argv[0]);
    return -1;
}
