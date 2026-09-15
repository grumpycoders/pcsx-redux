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

#include "supportpsx/dct.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <cmath>
#include <numbers>

#include "support/cpu-features.h"

#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64) || defined(_M_AMD64)
#define DCT_X86
#if defined(__GNUC__) || defined(__clang__)
#define DCT_AVX2_FUNC [[gnu::target("avx2")]]
#else
#define DCT_AVX2_FUNC
#endif
#include <immintrin.h>
#endif

namespace {

// SIMD batch width: one lane per block. 16 int16 lanes is one AVX2 register and
// is also a perfectly reasonable unroll factor for the scalar lane, so both lanes
// run the identical loop structure over the identical memory layout. That is the
// whole reason for batching across blocks rather than across the eight
// coefficients of one block: a row-per-register kernel is a different algorithm
// on every register width and needs transposes that this one does not have.
constexpr int kBatch = 16;

constexpr int kFixedBits = 14;
constexpr int kRound = 1 << (kFixedBits - 1);

inline int16_t saturate16(int32_t v) {
    if (v > 32767) return 32767;
    if (v < -32768) return -32768;
    return static_cast<int16_t>(v);
}

// Scalar lane. c is batch-major: c[coefficient * kBatch + lane].
void dctBatchScalar(int16_t *c, const int16_t *basis) {
    int16_t mid[64 * kBatch];
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            int32_t acc[kBatch];
            for (int l = 0; l < kBatch; l++) acc[l] = 0;
            for (int k = 0; k < 8; k++) {
                const int32_t b = basis[8 * i + k];
                const int16_t *src = c + (8 * j + k) * kBatch;
                for (int l = 0; l < kBatch; l++) acc[l] += static_cast<int32_t>(src[l]) * b;
            }
            int16_t *dst = mid + (8 * i + j) * kBatch;
            for (int l = 0; l < kBatch; l++) dst[l] = saturate16((acc[l] + kRound) >> kFixedBits);
        }
    }
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            int32_t acc[kBatch];
            for (int l = 0; l < kBatch; l++) acc[l] = 0;
            for (int k = 0; k < 8; k++) {
                const int32_t b = basis[8 * i + k];
                const int16_t *src = mid + (8 * j + k) * kBatch;
                for (int l = 0; l < kBatch; l++) acc[l] += static_cast<int32_t>(src[l]) * b;
            }
            int16_t *dst = c + (8 * i + j) * kBatch;
            for (int l = 0; l < kBatch; l++) dst[l] = saturate16((acc[l] + kRound) >> kFixedBits);
        }
    }
}

// Scalar twin of _mm256_mulhrs_epi16: (a*b + 0x4000) >> 15, low 16 bits, no
// saturation. Intel's semantics exactly; the FastMatrix lanes are only
// bit-identical because this matches.
inline int16_t mulhrs(int16_t a, int16_t b) {
    return static_cast<int16_t>((static_cast<int32_t>(a) * static_cast<int32_t>(b) + 0x4000) >> 15);
}

inline int16_t addsSat(int16_t a, int16_t b) { return saturate16(static_cast<int32_t>(a) + static_cast<int32_t>(b)); }

// FastMatrix scalar lane. Narrows after every multiply instead of accumulating in
// int32, which is what makes the 16-lane int16 vector form possible.
void dctBatchFastScalar(int16_t *c, const int16_t *basisQ15) {
    int16_t mid[64 * kBatch];
    auto pass = [&](const int16_t *src, int16_t *dst) {
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                int16_t acc[kBatch];
                for (int l = 0; l < kBatch; l++) acc[l] = 0;
                for (int k = 0; k < 8; k++) {
                    const int16_t b = basisQ15[8 * i + k];
                    const int16_t *p = src + (8 * j + k) * kBatch;
                    for (int l = 0; l < kBatch; l++) acc[l] = addsSat(acc[l], mulhrs(p[l], b));
                }
                int16_t *d = dst + (8 * i + j) * kBatch;
                for (int l = 0; l < kBatch; l++) d[l] = acc[l];
            }
        }
    };
    pass(c, mid);
    pass(mid, c);
}


// FastSymmetric. One 1D pass, batch-major, Q15 arithmetic.
//
// s_k = x_k + x_(7-k), d_k = x_k - x_(7-k), k = 0..3.  Even output rows of a
// symmetric basis depend only on s, odd rows only on d, so each output is a
// 4-term dot product instead of an 8-term one: 22 multiplies per pass against 64.
// Exact decomposition; the only error is the Q15 rounding, of which there is less
// than FastMatrix does.
//
// The scalar and AVX2 bodies below are the SAME algebra over different primitive
// sets (adds/subs/mulhrs). Keeping them textually parallel is the only reason the
// bit-identity test passes, so do not "simplify" one of them alone.
void dctSymPassScalar(const int16_t *src, int16_t *dst, const int16_t *q15) {
    for (int j = 0; j < 8; j++) {
        int16_t sv[4][kBatch], dv[4][kBatch];
        for (int k = 0; k < 4; k++) {
            const int16_t *a = src + (8 * j + k) * kBatch;
            const int16_t *b = src + (8 * j + (7 - k)) * kBatch;
            for (int l = 0; l < kBatch; l++) {
                sv[k][l] = addsSat(a[l], b[l]);
                dv[k][l] = saturate16(static_cast<int32_t>(a[l]) - static_cast<int32_t>(b[l]));
            }
        }
        for (int i = 0; i < 8; i++) {
            const int16_t(*in)[kBatch] = (i & 1) ? dv : sv;
            int16_t *d = dst + (8 * i + j) * kBatch;
            for (int l = 0; l < kBatch; l++) {
                int16_t acc = 0;
                for (int k = 0; k < 4; k++) acc = addsSat(acc, mulhrs(in[k][l], q15[8 * i + k]));
                d[l] = acc;
            }
        }
    }
}

void dctBatchSymScalar(int16_t *c, const int16_t *q15) {
    int16_t mid[64 * kBatch];
    dctSymPassScalar(c, mid, q15);
    dctSymPassScalar(mid, c, q15);
}

#ifdef DCT_X86
DCT_AVX2_FUNC void dctSymPassAvx2(const int16_t *src, int16_t *dst, const int16_t *q15) {
    for (int j = 0; j < 8; j++) {
        __m256i sv[4], dv[4];
        for (int k = 0; k < 4; k++) {
            const __m256i a = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(src + (8 * j + k) * kBatch));
            const __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(src + (8 * j + (7 - k)) * kBatch));
            sv[k] = _mm256_adds_epi16(a, b);
            dv[k] = _mm256_subs_epi16(a, b);
        }
        for (int i = 0; i < 8; i++) {
            const __m256i *in = (i & 1) ? dv : sv;
            __m256i acc = _mm256_setzero_si256();
            for (int k = 0; k < 4; k++) {
                acc = _mm256_adds_epi16(acc, _mm256_mulhrs_epi16(in[k], _mm256_set1_epi16(q15[8 * i + k])));
            }
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(dst + (8 * i + j) * kBatch), acc);
        }
    }
}

DCT_AVX2_FUNC void dctBatchSymAvx2(int16_t *c, const int16_t *q15) {
    alignas(32) int16_t mid[64 * kBatch];
    dctSymPassAvx2(c, mid, q15);
    dctSymPassAvx2(mid, c, q15);
}

DCT_AVX2_FUNC void dctFastPassAvx2(const int16_t *src, int16_t *dst, const int16_t *basisQ15) {
    for (int i = 0; i < 8; i++) {
        __m256i bv[8];
        for (int k = 0; k < 8; k++) bv[k] = _mm256_set1_epi16(basisQ15[8 * i + k]);
        for (int j = 0; j < 8; j++) {
            __m256i acc = _mm256_setzero_si256();
            for (int k = 0; k < 8; k++) {
                const __m256i sv = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(src + (8 * j + k) * kBatch));
                acc = _mm256_adds_epi16(acc, _mm256_mulhrs_epi16(sv, bv[k]));
            }
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(dst + (8 * i + j) * kBatch), acc);
        }
    }
}

DCT_AVX2_FUNC void dctBatchFastAvx2(int16_t *c, const int16_t *basisQ15) {
    alignas(32) int16_t mid[64 * kBatch];
    dctFastPassAvx2(c, mid, basisQ15);
    dctFastPassAvx2(mid, c, basisQ15);
}

// AVX2 lane. Deliberately accumulates in int32 and saturates on narrowing, which
// makes it BIT-IDENTICAL to the scalar lane. A 16-lane int16 path using
// _mm256_mulhrs_epi16 is about 1.6x faster and is NOT bit-identical: measured max
// absolute deviation from a double-precision reference is 8.75 against 1.25 for
// this one. An encoder whose output depends on which machine ran it is a bad
// surprise to hand someone, so the accurate lane is the default. The fast one is
// worth adding behind an explicit opt-in, not behind a CPU probe.
DCT_AVX2_FUNC void dctPassAvx2(const int16_t *src, int16_t *dst, const int32_t *basis32) {
    const __m256i round = _mm256_set1_epi32(kRound);
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            __m256i accLo = _mm256_setzero_si256();
            __m256i accHi = _mm256_setzero_si256();
            for (int k = 0; k < 8; k++) {
                const __m256i s = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(src + (8 * j + k) * kBatch));
                const __m256i b = _mm256_set1_epi32(basis32[8 * i + k]);
                const __m256i sLo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(s));
                const __m256i sHi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(s, 1));
                accLo = _mm256_add_epi32(accLo, _mm256_mullo_epi32(sLo, b));
                accHi = _mm256_add_epi32(accHi, _mm256_mullo_epi32(sHi, b));
            }
            accLo = _mm256_srai_epi32(_mm256_add_epi32(accLo, round), kFixedBits);
            accHi = _mm256_srai_epi32(_mm256_add_epi32(accHi, round), kFixedBits);
            // packs_epi32 saturates (matching saturate16) but interleaves the two
            // 128-bit halves, so undo that with a 64-bit lane permute.
            __m256i packed = _mm256_packs_epi32(accLo, accHi);
            packed = _mm256_permute4x64_epi64(packed, 0xd8);
            _mm256_storeu_si256(reinterpret_cast<__m256i *>(dst + (8 * i + j) * kBatch), packed);
        }
    }
}

DCT_AVX2_FUNC void dctBatchAvx2(int16_t *c, const int32_t *basis32) {
    alignas(32) int16_t mid[64 * kBatch];
    dctPassAvx2(c, mid, basis32);
    dctPassAvx2(mid, c, basis32);
}
#endif

}  // namespace

const PCSX::DCT::Basis &PCSX::DCT::standardBasis() {
    static const Basis s_basis = [] {
        // cos(n * pi / 16) / 2, Q14. Same table the MDEC's own command 3 is handed
        // by every shipping title, and the same one psxavenc builds from its SFn
        // constants.
        double sf[8];
        for (int n = 0; n < 8; n++) sf[n] = cos(n * std::numbers::pi / 16.0) / 2.0;
        static const int idx[8][8] = {{0, 0, 0, 0, 0, 0, 0, 0},    {1, 3, 5, 7, -7, -5, -3, -1},
                                      {2, 6, -6, -2, -2, -6, 6, 2}, {3, -7, -1, -5, 5, 1, 7, -3},
                                      {4, -4, -4, 4, 4, -4, -4, 4}, {5, -1, 7, 3, -3, -7, 1, -5},
                                      {6, -2, 2, -6, -6, 2, -2, 6}, {7, -5, 3, -1, 1, -3, 5, -7}};
        Basis b{};
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                const int k = idx[i][j];
                const double v = (k < 0) ? -sf[-k] : sf[k];
                b[i * 8 + j] = static_cast<int16_t>(lrint(v * 16384.0));
            }
        }
        return b;
    }();
    return s_basis;
}

void PCSX::DCT::transformBlockReference(int16_t *block, const Basis &basis, Transform transform) {
    if (transform == Transform::FastSymmetric) {
        int16_t q15[64];
        for (int i = 0; i < 64; i++) q15[i] = saturate16(static_cast<int32_t>(basis[i]) * 2);
        int16_t mid[64];
        auto pass = [&](const int16_t *src, int16_t *dst) {
            for (int j = 0; j < 8; j++) {
                int16_t sv[4], dv[4];
                for (int k = 0; k < 4; k++) {
                    sv[k] = addsSat(src[8 * j + k], src[8 * j + (7 - k)]);
                    dv[k] = saturate16(static_cast<int32_t>(src[8 * j + k]) -
                                       static_cast<int32_t>(src[8 * j + (7 - k)]));
                }
                for (int i = 0; i < 8; i++) {
                    const int16_t *in = (i & 1) ? dv : sv;
                    int16_t acc = 0;
                    for (int k = 0; k < 4; k++) acc = addsSat(acc, mulhrs(in[k], q15[8 * i + k]));
                    dst[8 * i + j] = acc;
                }
            }
        };
        pass(block, mid);
        pass(mid, block);
        return;
    }
    if (transform == Transform::FastMatrix) {
        int16_t q15[64];
        for (int i = 0; i < 64; i++) q15[i] = saturate16(static_cast<int32_t>(basis[i]) * 2);
        int16_t mid[64];
        auto pass = [&](const int16_t *src, int16_t *dst) {
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < 8; j++) {
                    int16_t acc = 0;
                    for (int k = 0; k < 8; k++) acc = addsSat(acc, mulhrs(src[8 * j + k], q15[8 * i + k]));
                    dst[8 * i + j] = acc;
                }
            }
        };
        pass(block, mid);
        pass(mid, block);
        return;
    }
    int16_t mid[64];
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            int32_t v = 0;
            for (int k = 0; k < 8; k++) v += static_cast<int32_t>(block[8 * j + k]) * basis[8 * i + k];
            mid[8 * i + j] = saturate16((v + kRound) >> kFixedBits);
        }
    }
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            int32_t v = 0;
            for (int k = 0; k < 8; k++) v += static_cast<int32_t>(mid[8 * j + k]) * basis[8 * i + k];
            block[8 * i + j] = saturate16((v + kRound) >> kFixedBits);
        }
    }
}

bool PCSX::DCT::basisIsSymmetric(const Basis &basis) {
    for (int i = 0; i < 8; i++) {
        const int sign = (i & 1) ? -1 : 1;
        for (int j = 0; j < 4; j++) {
            if (basis[i * 8 + (7 - j)] != sign * basis[i * 8 + j]) return false;
        }
    }
    return true;
}

PCSX::DCT::Encoder::Encoder(unsigned threads, Transform transform, Basis basis)
    : m_basis(basis), m_transform(transform) {
    if (transform == Transform::FastSymmetric && !basisIsSymmetric(basis)) {
        // Loudly, at construction. The decomposition simply cannot express this
        // basis, and silently falling back to another Transform would hand the
        // caller different coefficients than the ones they selected.
        throw std::invalid_argument("DCT::Transform::FastSymmetric requires a basis with even/odd symmetry");
    }
    // Q14 -> Q15. The standard basis peaks at 0.5 so this never saturates, but a
    // caller-supplied basis with a coefficient at or above 1.0 would, hence the clamp.
    for (int i = 0; i < 64; i++) {
        const int32_t v = static_cast<int32_t>(m_basis[i]) * 2;
        m_basisQ15[i] = saturate16(v);
    }
    m_threadCount = threads ? threads : std::max(1u, std::thread::hardware_concurrency());
#ifdef DCT_X86
    // The override exists so the scalar lane stays reachable and therefore
    // testable on a machine that has AVX2, and so a lane can be bisected out in
    // the field without a rebuild. It can only ever turn features off.
    m_useAvx2 = CPUFeatures::get().avx2 && (getenv("PCSX_DCT_NO_SIMD") == nullptr);
#endif
    m_threads.reserve(m_threadCount);
    for (unsigned i = 0; i < m_threadCount; i++) m_threads.emplace_back([this] { worker(); });
}

PCSX::DCT::Encoder::~Encoder() {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shutdown = true;
    }
    m_cv.notify_all();
    for (auto &t : m_threads) t.join();
}

const char *PCSX::DCT::Encoder::lane() const { return m_useAvx2 ? "avx2" : "scalar"; }

PCSX::DCT::Promise PCSX::DCT::Encoder::submit(const Frame &frame, std::span<int16_t> out) {
    Job job;
    job.frame = frame;
    job.out = out;
    auto future = job.result.get_future();
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push_back(std::move(job));
    }
    m_cv.notify_one();
    return Promise(std::move(future));
}

namespace {

// Where block `index` lives in the source frame. MDEC block order within a
// macroblock is Cr, Cb, Y1, Y2, Y3, Y4.
struct BlockSite {
    const uint8_t *base;
    uint32_t stride;
    uint32_t pixelStride;
};

BlockSite locate(const PCSX::DCT::Frame &f, uint32_t mbX, uint32_t mbY, uint32_t sub) {
    switch (sub) {
        case 0:
            return {f.cr + f.cStride * (mbY * 8) + f.cPixelStride * (mbX * 8), f.cStride, f.cPixelStride};
        case 1:
            return {f.cb + f.cStride * (mbY * 8) + f.cPixelStride * (mbX * 8), f.cStride, f.cPixelStride};
        default: {
            const uint32_t dx = ((sub - 2) & 1) * 8;
            const uint32_t dy = ((sub - 2) >> 1) * 8;
            return {f.y + f.yStride * (mbY * 16 + dy) + (mbX * 16 + dx), f.yStride, 1};
        }
    }
}

}  // namespace

void PCSX::DCT::Encoder::worker() {
    std::array<int32_t, 64> basis32{};
    for (int i = 0; i < 64; i++) basis32[i] = m_basis[i];

    for (;;) {
        Job job;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] { return m_shutdown || !m_queue.empty(); });
            if (m_queue.empty()) {
                if (m_shutdown) return;
                continue;
            }
            job = std::move(m_queue.front());
            m_queue.pop_front();
        }

        const Frame &f = job.frame;
        Result result;
        if (!f.y || !f.cb || !f.cr || (f.width % 16) || (f.height % 16) || !f.width || !f.height ||
            job.out.size() < requiredCoefficientCount(f.width, f.height)) {
            result.failed = true;
            job.result.set_value(std::move(result));
            continue;
        }

        result.macroblocksX = f.width / 16;
        result.macroblocksY = f.height / 16;
        const uint32_t macroblocks = result.macroblocksX * result.macroblocksY;
        result.blockCount = macroblocks * 6;

        alignas(32) int16_t batch[64 * kBatch];

        for (uint32_t base = 0; base < result.blockCount; base += kBatch) {
            const uint32_t count = std::min<uint32_t>(kBatch, result.blockCount - base);
            // The tail of a frame whose block count is not a multiple of kBatch is
            // zero-filled rather than handled by a second code path. 1800 blocks
            // for 320x240 leaves a remainder of 8, so this is the common case and
            // not an edge case; one code path is worth 0.4% of wasted transform.
            memset(batch, 0, sizeof(batch));
            for (uint32_t l = 0; l < count; l++) {
                const uint32_t bi = base + l;
                const uint32_t mb = bi / 6;
                const BlockSite site = locate(f, mb % result.macroblocksX, mb / result.macroblocksX, bi % 6);
                for (uint32_t row = 0; row < 8; row++) {
                    const uint8_t *p = site.base + site.stride * row;
                    for (uint32_t col = 0; col < 8; col++) {
                        batch[(row * 8 + col) * kBatch + l] = static_cast<int16_t>(p[col * site.pixelStride]) - 128;
                    }
                }
            }

            switch (m_transform) {
                case Transform::FastSymmetric:
#ifdef DCT_X86
                    if (m_useAvx2) {
                        dctBatchSymAvx2(batch, m_basisQ15.data());
                        break;
                    }
#endif
                    dctBatchSymScalar(batch, m_basisQ15.data());
                    break;
                case Transform::FastMatrix:
#ifdef DCT_X86
                    if (m_useAvx2) {
                        dctBatchFastAvx2(batch, m_basisQ15.data());
                        break;
                    }
#endif
                    dctBatchFastScalar(batch, m_basisQ15.data());
                    break;
                case Transform::ExactMatrix:
                default:
#ifdef DCT_X86
                    if (m_useAvx2) {
                        dctBatchAvx2(batch, basis32.data());
                        break;
                    }
#endif
                    dctBatchScalar(batch, m_basis.data());
                    break;
            }

            for (uint32_t l = 0; l < count; l++) {
                int16_t *out = job.out.data() + static_cast<size_t>(base + l) * 64;
                for (uint32_t k = 0; k < 64; k++) out[k] = batch[k * kBatch + l];
            }
        }

        job.result.set_value(std::move(result));
    }
}

// ---------------------------------------------------------------------------
// Run-level packing and rate control.

namespace {

// psx-spx zigzag: c_zscan[k] is the natural-order index of zigzag position k.
constexpr int c_packZscan[64] = {
    0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,  12, 19, 26, 33, 40, 48,
    41, 34, 27, 20, 13, 6,  7,  14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23,
    30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
};

// The table every shipping encoder uses. Not an all-ones table: the run-level DC
// field is signed TEN BITS and an unquantized DC runs to about 1150, so identity
// quant clips every block brighter than mid-grey.
constexpr uint8_t c_packStandardQuant[64] = {
    2,  16, 19, 22, 26, 27, 29, 34, 16, 16, 22, 24, 27, 29, 34, 37, 19, 22, 26, 27, 29, 34,
    34, 38, 22, 22, 26, 27, 29, 34, 37, 40, 22, 26, 27, 29, 32, 35, 40, 48, 26, 27, 29, 32,
    35, 40, 48, 58, 26, 27, 29, 34, 38, 46, 56, 69, 27, 29, 35, 38, 46, 56, 69, 83,
};

int clampField10(int v, uint32_t &clipped) {
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

int divRoundPack(int num, int den) {
    if (den == 0) return 0;
    return (num < 0) ? -((-num + den / 2) / den) : ((num + den / 2) / den);
}

// One 8x8 block, appended. Returns nothing; the caller tracks sizes by watching
// `out`. Calibration constants are MEASURED, not derived - harness in
// learnings/mdec-dct-bench:
//   the forward transform puts 16*luma in blk[0] and real_idct_core turns a DC of
//   D back into D/8, so the composite DC gain is 2 and the divisor is qt[0]*2;
//   the AC composite gain is sqrt(2) across all seven frequencies, because the
//   psx-spx scale matrix carries the orthonormal DCT's 1/sqrt(2) on its DC row and
//   the forward basis does not, and 5793/1024 is 8/sqrt(2) in fixed point.
// ⚠ q_scale appears in the AC divisor and NOT the DC one. That mirrors the
// hardware, measured 2026-09-14: arms holding everything but q_scale and running
// it at 8 against 63 decode byte-identical, so the DC genuinely ignores it.
void packBlock(const int16_t *blk, const uint8_t *qt, int qScale, std::vector<uint16_t> &out, uint32_t &clippedAc,
               uint32_t &clippedDc) {
    const int dcDen = (qt[0] ? qt[0] : 1) * 2;
    const int dc = clampField10(divRoundPack(blk[0], dcDen), clippedDc);
    out.push_back(static_cast<uint16_t>(((qScale & 0x3f) << 10) | (dc & 0x3ff)));
    int run = 0;
    for (int k = 1; k < 64; k++) {
        const int den = qt[k] * qScale;
        const int ac = clampField10(divRoundPack(blk[c_packZscan[k]] * 5793, (den ? den : 1) * 1024), clippedAc);
        if (ac == 0) {
            run++;
            continue;
        }
        out.push_back(static_cast<uint16_t>(((run & 0x3f) << 10) | (ac & 0x3ff)));
        run = 0;
    }
    out.push_back(0xfe00);
}

}  // namespace

const uint8_t *PCSX::DCT::standardQuantTable() { return c_packStandardQuant; }

int PCSX::DCT::qualityToQScale(int quality) {
    quality = std::clamp(quality, 1, 100);
    // 63^((100-q)/99): 100 -> 1, 50 -> 8, 1 -> 63.
    const double e = static_cast<double>(100 - quality) / 99.0;
    const int v = static_cast<int>(std::lround(std::pow(63.0, e)));
    return std::clamp(v, 1, 63);
}

void PCSX::DCT::scaleQuantTable(const uint8_t *in, uint8_t *out, int quality) {
    if (!in) in = c_packStandardQuant;
    quality = std::clamp(quality, 1, 100);
    // The IJG curve. Below 50 the divisors grow without bound as quality falls;
    // above it they shrink linearly to 2% of nominal at 100.
    const int scale = (quality < 50) ? (5000 / quality) : (200 - quality * 2);
    for (int i = 0; i < 64; i++) {
        const int v = (in[i] * scale + 50) / 100;
        out[i] = static_cast<uint8_t>(std::clamp(v, 1, 255));
    }
}

PCSX::DCT::PackResult PCSX::DCT::pack(std::span<const int16_t> coefficients, const Result &shape,
                                      const QuantTables &tables, int qScale, std::vector<uint16_t> &out,
                                      const RateControl &rateControl) {
    PackResult result;
    if (shape.failed || shape.blockCount == 0 || (shape.blockCount % 6) != 0) {
        result.failed = true;
        return result;
    }
    if (coefficients.size() < static_cast<size_t>(shape.blockCount) * 64) {
        result.failed = true;
        return result;
    }
    const uint8_t *qy = tables.y ? tables.y : c_packStandardQuant;
    const uint8_t *quv = tables.uv ? tables.uv : c_packStandardQuant;
    const int initial = std::clamp(qScale, 1, 63);

    const uint32_t macroblocks = shape.blockCount / 6;
    for (uint32_t mb = 0; mb < macroblocks; mb++) {
        const size_t acceptedSoFar = out.size();
        int q = initial;
        uint32_t attempt = 0;
        uint32_t acHere = 0, dcHere = 0;
        for (;;) {
            out.resize(acceptedSoFar);
            acHere = 0;
            dcHere = 0;
            for (uint32_t i = 0; i < 6; i++) {
                const size_t b = static_cast<size_t>(mb) * 6 + i;
                packBlock(coefficients.data() + b * 64, (i < 2) ? quv : qy, q, out, acHere, dcHere);
            }
            result.attempts++;
            if (!rateControl) break;
            PackAttempt info;
            info.macroblock = mb;
            info.attempt = attempt;
            info.qScale = q;
            info.sizeHalfwords = out.size() - acceptedSoFar;
            info.totalHalfwords = out.size();
            info.clippedAc = acHere;
            info.clippedDc = dcHere;
            const auto next = rateControl(info);
            if (!next.has_value()) break;
            const int want = std::clamp(*next, 1, 63);
            // Two independent stops. Repeating a value means converged, which is
            // the common case. The hard cap is what a functor ALTERNATING between
            // two values needs: it never repeats consecutively, so the first test
            // alone loops forever. 64 is the count of distinct q_scale values, so
            // no search that makes progress can reach it.
            if (want == q) break;
            if (attempt + 1 >= 64) break;
            q = want;
            attempt++;
        }
        result.clippedAc += acHere;
        result.clippedDc += dcHere;
    }

    // psx-spx: MDEC(1) parameters want padding to 40h halfwords so the DMA block
    // count is a whole number of 20h-word blocks. A half block hangs DMA0.
    while (out.size() % 64) out.push_back(0xfe00);
    result.halfwords = out.size();
    return result;
}
