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

#pragma once

#include <stdint.h>

#include <array>
#include <condition_variable>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>

namespace PCSX {

namespace DCT {

// Forward 8x8 DCT stage of an MDEC-style encoder.
//
// Scope is deliberately just the transform: raw image in, dequantized-domain
// coefficients out. Quantization, run-length coding, entropy coding, sector
// muxing and disc layout are all somebody else's problem.
//
// The transform is a general 8x8 matrix multiply against a settable basis, not a
// hardwired DCT. This mirrors the MDEC itself, whose command 3 uploads a 64-entry
// signed halfword table and which then computes dst = src * table without caring
// whether the table holds cosines. An encoder for a non-standard basis has to be
// able to express the matching forward transform, so the general form is the one
// implemented here.

// Which transform an Encoder runs. This is a USER choice, deliberately, because
// the variants do not produce identical coefficients and the difference is a
// quality/speed tradeoff somebody should be making on purpose.
//
// Orthogonal to this, and NOT a user choice: each variant has a scalar lane and a
// vectorized lane selected by CPUFeatures at construction. Every lane of a given
// variant is bit-identical to every other lane of that variant, verified by test.
// So output depends on the Transform you asked for and never on the machine that
// ran it.
enum class Transform {
    // General basis, int32 accumulation, saturating narrow. Matches
    // transformBlockReference() bit for bit. The default.
    ExactMatrix,
    // General basis, Q15 round-and-narrow per multiply (the shape
    // _mm256_mulhrs_epi16 implements natively). Faster and less accurate.
    FastMatrix,
    // FastMatrix's arithmetic plus the even/odd butterfly: with s_k = x_k + x_7-k
    // and d_k = x_k - x_7-k, the symmetric rows of the basis consume only s and
    // the antisymmetric rows only d, which is 22 multiplies per 1D pass instead of
    // 64. That decomposition is EXACT, not an approximation, so the only error is
    // the Q15 rounding, and there is less of it than FastMatrix has because there
    // are fewer roundings.
    //
    // Requires a basis whose even rows are symmetric and odd rows antisymmetric
    // about the centre. The standard MDEC basis is. A basis that is not will throw
    // from the Encoder constructor rather than quietly producing nonsense, and
    // note that this is a weaker requirement than "the standard basis": a custom
    // symmetric basis still works here.
    FastSymmetric,
};



// 64 signed Q14 coefficients, row-major. Row i column k is the weight of input k
// in output i of a 1D 8-point transform.
using Basis = std::array<int16_t, 64>;

// The standard MDEC basis: cos(n*pi/16)/2 in Q14, the table every shipping game
// uploads.
const Basis &standardBasis();

// True if `basis` has the even/odd symmetry Transform::FastSymmetric needs: even
// rows symmetric about the centre, odd rows antisymmetric.
bool basisIsSymmetric(const Basis &basis);

// Chroma siting is 4:2:0. cPixelStride lets a caller pass interleaved chroma
// (the shape libswscale hands back for NV-style formats) without repacking:
// set cb and cr to adjacent bytes of one plane, cStride to the plane pitch, and
// cPixelStride to 2.
struct Frame {
    const uint8_t *y = nullptr;
    const uint8_t *cb = nullptr;
    const uint8_t *cr = nullptr;
    uint32_t width = 0;   // must be a multiple of 16
    uint32_t height = 0;  // must be a multiple of 16
    uint32_t yStride = 0;
    uint32_t cStride = 0;
    uint32_t cPixelStride = 1;
};

// How many int16 the caller must provide for a frame of this size.
constexpr size_t requiredCoefficientCount(uint32_t width, uint32_t height) {
    return static_cast<size_t>(width / 16) * (height / 16) * 6 * 64;
}

// Metadata only. The coefficients went into the span the caller supplied, which
// is deliberate: allocating and zero-filling a per-frame output vector measured as
// the dominant cost of this stage at high thread counts, well above the transform
// it exists to carry.
//
// Layout in that span is block-major: 64 int16 per block, blocks in MDEC order
// within each macroblock (Cr, Cb, Y1, Y2, Y3, Y4), macroblocks in raster order.
// out.data() + 64 * n is block n.
//
// The kernel works batch-major internally (one SIMD lane per block) and
// de-interleaves on store. If a downstream stage is also vectorized, that
// de-interleave is waste and this is where a batch-major output option belongs.
struct Result {
    uint32_t blockCount = 0;
    uint32_t macroblocksX = 0;
    uint32_t macroblocksY = 0;
    bool failed = false;
};

// Handle on a unit of background work. Move-only; joining twice is a programming
// error and will throw, same as std::future.
class Promise {
  public:
    Promise() = default;
    Promise(Promise &&) = default;
    Promise &operator=(Promise &&) = default;
    Promise(const Promise &) = delete;
    Promise &operator=(const Promise &) = delete;

    bool valid() const { return m_future.valid(); }
    // True if get() would return without blocking.
    bool ready() const {
        return m_future.valid() && m_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    }
    void join() { m_future.wait(); }
    Result get() { return m_future.get(); }

  private:
    explicit Promise(std::future<Result> &&f) : m_future(std::move(f)) {}
    std::future<Result> m_future;
    friend class Encoder;
};

class Encoder {
  public:
    // threads == 0 means hardware_concurrency(). Note that scaling measured on a
    // 2-socket Haswell box tops out at the physical core count and regresses hard
    // past it, so hardware_concurrency() (which counts SMT siblings) is a ceiling
    // and not a recommendation.
    explicit Encoder(unsigned threads = 0, Transform transform = Transform::ExactMatrix,
                     Basis basis = standardBasis());
    ~Encoder();

    Encoder(const Encoder &) = delete;
    Encoder &operator=(const Encoder &) = delete;

    // The frame's pixels are READ and the output span is WRITTEN on a worker
    // thread at an unspecified later time. The caller owns both and must keep both
    // alive and untouched until the returned Promise has been joined. Nothing is
    // copied and nothing is allocated per frame.
    //
    // `out` must hold at least requiredCoefficientCount(frame.width, frame.height)
    // entries; a short span is reported as Result::failed rather than clipped.
    Promise submit(const Frame &frame, std::span<int16_t> out);

    // Which kernel lane the runtime probe selected, for logs. Not a correctness
    // knob: lanes of one Transform agree bit for bit.
    const char *lane() const;
    Transform transform() const { return m_transform; }

    unsigned threadCount() const { return m_threadCount; }

  private:
    struct Job {
        Frame frame;
        std::span<int16_t> out;
        std::promise<Result> result;
    };

    void worker();

    Basis m_basis;
    std::array<int16_t, 64> m_basisQ15{};
    Transform m_transform = Transform::ExactMatrix;
    unsigned m_threadCount = 0;
    std::vector<std::thread> m_threads;
    std::deque<Job> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_shutdown = false;
    bool m_useAvx2 = false;
};

// Exposed for testing: transform one 8x8 block in place, block-major, scalar,
// against the given basis, using the given variant's arithmetic. This is the
// reference every lane of that variant must match bit for bit.
void transformBlockReference(int16_t *block, const Basis &basis, Transform transform = Transform::ExactMatrix);

}  // namespace DCT

}  // namespace PCSX
