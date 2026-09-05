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

#include <algorithm>
#include <cstdint>
#include <vector>

#include "gtest/gtest.h"
#include "supportpsx/ucl-utils.h"
#include "ucl/ucl.h"

// The build only links the SAFE decoder (n2e_ds.c renames the entry). It still
// performs the real overlapping write, so it is the correct round-trip decoder.
extern "C" int ucl_nrv2e_decompress_safe_8(const unsigned char* src, ucl_uint src_len, unsigned char* dst,
                                           ucl_uint* dst_len, void* wrkmem);

namespace {

std::vector<uint8_t> compress(const std::vector<uint8_t>& orig) {
    std::vector<uint8_t> comp(orig.size() * 12 / 10 + 4096);
    ucl_uint compLen = comp.size();
    int r = ucl_nrv2e_99_compress(orig.data(), orig.size(), comp.data(), &compLen, nullptr, 10, nullptr, nullptr);
    EXPECT_EQ(r, UCL_E_OK);
    comp.resize(compLen);
    return comp;
}

// Performs the real overlapping in-place decode: the compressed bytes live at
// buf[srcOff..], the output is written to buf[0..]. Returns true iff the decode
// reproduced `orig` exactly.
bool overlapDecodeReproduces(const std::vector<uint8_t>& comp, const std::vector<uint8_t>& orig, size_t srcOff) {
    std::vector<uint8_t> buf(orig.size() + srcOff + comp.size() + 64, 0);
    std::copy(comp.begin(), comp.end(), buf.begin() + srcOff);
    ucl_uint dstLen = orig.size();
    int r = ucl_nrv2e_decompress_safe_8(buf.data() + srcOff, comp.size(), buf.data(), &dstLen, nullptr);
    if (r != UCL_E_OK || dstLen != orig.size()) return false;
    return std::equal(orig.begin(), orig.end(), buf.begin());
}

// The computed margin must reconstruct exactly, AND be tight: one byte closer
// must corrupt. A loose (too-large) margin would be safe but is not what the
// single-pass measurement should ever produce.
void checkExactMargin(const std::vector<uint8_t>& orig) {
    auto comp = compress(orig);
    size_t margin = PCSX::UCLUtils::inPlaceOverlapMargin(comp.data(), comp.size(), orig.size());
    EXPECT_TRUE(overlapDecodeReproduces(comp, orig, margin))
        << "in-place decode at the computed margin did not reconstruct";
    if (margin > 0) {
        EXPECT_FALSE(overlapDecodeReproduces(comp, orig, margin - 1)) << "computed margin is not tight";
    }
}

std::vector<uint8_t> pseudoRandom(size_t n, uint32_t seed) {
    std::vector<uint8_t> v;
    v.reserve(n);
    uint32_t s = seed;
    for (size_t i = 0; i < n; i++) {
        s = s * 1103515245u + 12345u;
        v.push_back(static_cast<uint8_t>(s >> 16));
    }
    return v;
}

}  // namespace

TEST(PS1PackerOverlap, Compressible) {
    std::vector<uint8_t> v;
    for (int i = 0; i < 2000; i++) v.push_back(i & 1 ? 0xAA : 0x55);
    for (int i = 0; i < 4000; i++) v.push_back(0x00);
    checkExactMargin(v);
}

TEST(PS1PackerOverlap, PseudoRandom) { checkExactMargin(pseudoRandom(8192, 0x12345678)); }

TEST(PS1PackerOverlap, MixedTail) {
    auto v = pseudoRandom(4096, 0xC0FFEE11);
    for (int i = 0; i < 16384; i++) v.push_back(0x42);
    checkExactMargin(v);
}

TEST(PS1PackerOverlap, RepeatedText) {
    std::vector<uint8_t> v;
    const char* frag = "the quick brown fox jumps over the lazy dog. ";
    for (int i = 0; i < 400; i++)
        for (const char* p = frag; *p; p++) v.push_back(static_cast<uint8_t>(*p));
    checkExactMargin(v);
}

TEST(PS1PackerOverlap, TinyRle) { checkExactMargin(std::vector<uint8_t>(37, 0x7F)); }

TEST(PS1PackerOverlap, TinyLiteral) { checkExactMargin({'H', 'e', 'l', 'l', 'o'}); }

// The regression this whole change exists for: a highly compressible head races
// the decompressor's write head far ahead of its read head, so the required
// margin lands well above the old hardcoded 16-byte gap. If the margin ever
// silently reverts to a constant, this reconstruction fails.
TEST(PS1PackerOverlap, CompressibleHeadDefeatsFixedGap) {
    std::vector<uint8_t> v;
    for (int i = 0; i < 20000; i++) v.push_back(0x00);
    auto tail = pseudoRandom(12000, 0xBEEFCAFE);
    v.insert(v.end(), tail.begin(), tail.end());

    auto comp = compress(v);
    size_t margin = PCSX::UCLUtils::inPlaceOverlapMargin(comp.data(), comp.size(), v.size());
    size_t gain = v.size() > comp.size() ? v.size() - comp.size() : 0;
    // The gap the old fixed constant had to cover is (margin - gain); this
    // payload needs far more than 16, which is exactly why the constant was a bug.
    EXPECT_GT(margin - gain, static_cast<size_t>(16));
    EXPECT_TRUE(overlapDecodeReproduces(comp, v, margin));
    EXPECT_FALSE(overlapDecodeReproduces(comp, v, margin - 1));
}
