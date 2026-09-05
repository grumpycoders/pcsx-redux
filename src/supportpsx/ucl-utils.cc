/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

// Computes the exact overlap margin required to safely decompress an NRV2E
// stream over itself, as produced by ucl_nrv2e_99_compress and consumed by the
// MIPS unpacker in n2e-d.S / n2e-d.h.
//
// In-place decompression only works if the compressed data sits far enough
// "above" the decompression target that the decompressor's write head (olen)
// never overtakes its read head (ilen). ps1-packer historically assumed a fixed
// 16-byte gap past the end of the decompressed image; that is a data-dependent
// quantity, not a constant, and a stream whose worst-case match lands late
// enough will silently corrupt on decompression.
//
// This walks the real bitstream exactly as the decompressor would -- the same
// token grammar as third_party/ucl/src/n2e_d.c and the same byte-consumption
// cadence as the _8 bit-buffer (which n2e-d.S's getbit reproduces) -- but writes
// nothing, and instead records the largest value of (olen - ilen) seen across
// the whole stream. That maximum is precisely the smallest src_off for which an
// overlapping decode from &buf[src_off] -> &buf[0] is safe: i.e. the value
// ucl_nrv2e_test_overlap_8 would accept, minimized in a single pass.
//
// Keep this in sync with the NRV2E grammar in n2e_d.c and the getbit cadence in
// n2e-d.S. It deliberately does not depend on the vendored ucl sources.

#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "supportpsx/ucl-utils.h"

size_t PCSX::UCLUtils::inPlaceOverlapMargin(const uint8_t *src, size_t srcLen, size_t expectedDstLen) {
    uint32_t bb = 0;
    uint32_t last_m_off = 1;
    size_t ilen = 0, olen = 0;
    int64_t peak = 0;
    bool overrun = false;

    auto bad = []() -> void {
        throw std::runtime_error("UCLUtils::inPlaceOverlapMargin: malformed NRV2E stream while measuring in-place overlap margin.");
    };

    // getbit_8-equivalent: MSB-first, one source byte per 8 bits, refill when the
    // low-7 sentinel window clears. This matches n2e-d.S's getbit cadence exactly,
    // so `ilen` tracks the real decompressor's source consumption.
    auto getbit = [&]() -> uint32_t {
        if ((bb & 0x7f) == 0) {
            if (ilen >= srcLen) {
                overrun = true;
                return 0;
            }
            bb = static_cast<uint32_t>(src[ilen++]) * 2 + 1;
        } else {
            bb *= 2;
        }
        return (bb >> 8) & 1;
    };
    auto sample = [&]() {
        int64_t diff = static_cast<int64_t>(olen) - static_cast<int64_t>(ilen);
        if (diff > peak) peak = diff;
    };

    for (;;) {
        uint32_t m_off, m_len;

        // Literal run: read and write advance in lockstep, so the gap is
        // unchanged here. The peak only ever lands on a match, but we sample
        // anyway to mirror the decoder's check points and stay conservative.
        while (getbit()) {
            if (overrun || ilen >= srcLen || (expectedDstLen && olen >= expectedDstLen)) bad();
            olen++;
            ilen++;
            sample();
        }

        // Match offset, NRV2E gamma-coded two bits at a time.
        m_off = 1;
        for (;;) {
            m_off = m_off * 2 + getbit();
            if (overrun || m_off > 0xffffffu + 3) bad();
            if (getbit()) break;
            m_off = (m_off - 1) * 2 + getbit();
        }
        if (m_off == 2) {
            m_off = last_m_off;  // repeat last offset (the NRV2E rep-match)
            m_len = getbit();
        } else {
            if (ilen >= srcLen) bad();
            m_off = (m_off - 3) * 256 + src[ilen++];
            if (m_off == 0xffffffffu) break;  // end-of-stream marker
            m_len = (m_off ^ 0xffffffffu) & 1;
            m_off >>= 1;
            last_m_off = ++m_off;
        }

        // Match length, gamma-coded, plus the +1 for far offsets.
        if (m_len) {
            m_len = 1 + getbit();
        } else if (getbit()) {
            m_len = 3 + getbit();
        } else {
            m_len++;
            do {
                m_len = m_len * 2 + getbit();
                if (overrun) bad();
            } while (!getbit());
            m_len += 3;
        }
        m_len += (m_off > 0x500);
        if (overrun || m_off > olen) bad();

        // Match copy: the write head leaps forward by m_len + 1 bytes while the
        // read head stays put. This is the checkpoint where the overlap peaks.
        olen += m_len + 1;
        if (expectedDstLen && olen > expectedDstLen) bad();
        sample();
    }

    if (overrun || (expectedDstLen && olen != expectedDstLen) || ilen != srcLen) bad();

    return peak < 0 ? 0 : static_cast<size_t>(peak);
}
