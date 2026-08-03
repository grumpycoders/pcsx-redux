// DIAGNOSTIC ONLY - not for upstream. Selects which shift stage in the voice
// path rounds instead of truncating, so a single binary can measure every
// candidate against the same page cache. Set SPU_ROUND_PROBE:
// BITMASK (combinable):
//   0/unset  baseline (arithmetic shift, floor, everywhere)
//   1        ADSR envelope: round to nearest
//   2        ADSR envelope: truncate toward zero
//   4        gaussian per-tap: round to nearest
//   8        gaussian per-tap: truncate toward zero
//  16        gaussian: sum four full-precision products, single SAR 15 at the end
//  32        gaussian: sum four full-precision products, round to nearest at the end
//  64        ADPCM filter: single combined sum with +32 rounding (nocash form)
#pragma once

#include <cstdlib>

namespace PCSX::SPU {
// DIAGNOSTIC: last gaussian tap inputs, so the offline solver can reconstruct
// every candidate formulation without another emulator run.
struct GaussProbe {
    int idx, w0, w1, w2, w3, type, seq;
    // DIAGNOSTIC: resampler cursor state, dumped rather than inferred. `consumed`
    // is the cumulative count of decoded source samples this voice has pulled
    // (every takeSample()), so it can be differenced against the predicted
    // seq*sinc/kUnity to find WHERE the two diverge instead of at what rate.
    long long consumed;
    int spos;     // fractional pitch position at emit time, 16.16
    int sinc;     // pitch step per output sample, 16.16
    int apos;     // ADPCM read cursor into the 28-sample block
    int curroff;  // decode cursor as a byte offset from the sample start
};
inline GaussProbe &gaussProbe() {
    static GaussProbe g{};
    return g;
}

inline int roundingProbe() {
    static const int mode = [] {
        const char *e = std::getenv("SPU_ROUND_PROBE");
        return e ? std::atoi(e) : 0;
    }();
    return mode;
}
}  // namespace PCSX::SPU
