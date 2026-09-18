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
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <thread>
#include <vector>

namespace PCSX {

namespace DCT {

// Forward 8x8 DCT stage of an MDEC-style encoder.
//
// Scope is the transform and the MDEC's own run-level packing: raw image in,
// either dequantized-domain coefficients (Encoder) or the halfword stream DMA0
// consumes (pack, below). Entropy coding, sector muxing and disc layout are still
// somebody else's problem.
//
// Packing lives here rather than in a tool because it is format knowledge - the
// 10-bit signed fields, the FE00h terminator, the DMA block padding and the
// dequantizer's exact divisors are properties of the MDEC, not of any one caller.
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

// ---------------------------------------------------------------------------
// Run-level packing, and rate control.
//
// Separate from Encoder deliberately. The transform is embarrassingly parallel
// and runs on the pool; rate control accumulates a budget in macroblock order and
// therefore has to be serial. Feed this the span Encoder wrote, on the caller's
// thread, and the split costs nothing: the DCT is the expensive half and it still
// runs N-wide.

// The two MDEC(2) tables. Both are 64 unsigned bytes. A null member means the
// standard table.
struct QuantTables {
    const uint8_t *y = nullptr;   // luminance, used for Y1..Y4
    const uint8_t *uv = nullptr;  // colour, used for Cb and Cr
};

// Reported to the rate-control functor after every packing attempt.
struct PackAttempt {
    uint32_t macroblock = 0;    // raster index
    uint32_t attempt = 0;       // 0 is the first pack of this macroblock
    int qScale = 0;             // what produced the sizes below
    size_t sizeHalfwords = 0;   // this macroblock alone
    size_t totalHalfwords = 0;  // accepted macroblocks so far, plus this one
    // Saturations of the 10-bit run-level field, split because the two have
    // DIFFERENT remedies and merging them hands the caller an ambiguous signal.
    // An AC clip is fixable from here: raise q_scale and re-pack. A DC clip is
    // NOT - the DC divisor is qt[0] alone and q_scale does not appear in it, so
    // no value this functor can return will help. A rate controller seeing
    // clippedDc should stop iterating and tell someone the TABLE is too fine.
    uint32_t clippedAc = 0;
    uint32_t clippedDc = 0;
};

// Called once per packing attempt, in macroblock raster order, on the caller's
// thread. Return the q_scale to try next, or nullopt to accept the attempt just
// reported.
//
// ⚠ The only per-macroblock knob the format has is q_scale, because it is the one
// quantization parameter carried IN the block stream. The quant tables arrive by
// their own MDEC(2) command, so they are frame-level and changing them mid-stream
// is not something MDEC(1) can express.
//
// A retry re-quantizes and re-packs without re-transforming, since the transform
// output does not depend on q_scale. An extra attempt costs the quantize and the
// RLE, never the DCT.
//
// A returned value outside 1..63 is clamped. Two things stop a functor hanging
// the encoder: repeating a q_scale is treated as accept, and attempts per
// macroblock are capped at 64, which is the number of distinct q_scale values.
// The cap is not redundant - a functor alternating between two values never
// repeats consecutively, so the first test alone would loop forever.
using RateControl = std::function<std::optional<int>(const PackAttempt &)>;

struct PackResult {
    size_t halfwords = 0;
    uint32_t clippedAc = 0;
    uint32_t clippedDc = 0;
    uint32_t attempts = 0;  // total across the frame; == macroblock count if no retries
    bool failed = false;
    // The q_scale range actually emitted. Rate control may raise or lower it per
    // macroblock, and BS cannot express that: its header carries QUANT once and
    // Sony's spec says in terms that every block is assumed to share it. Reported
    // rather than forbidden, so the container decides - toContainer(Bs) refuses a
    // frame where these differ, and the run-level containers do not care.
    int minQScale = 0;
    int maxQScale = 0;
};

// Pack a transformed frame into the MDEC run-level stream, appending to `out`.
//
// `shape` is the Result the Encoder returned for this same span. `qScale` is the
// initial value, 1..63; 0 is the format's no-quant-table mode and this does not
// emit it. With no `rateControl` every macroblock is packed once at `qScale`,
// which is the whole of the previous behaviour.
PackResult pack(std::span<const int16_t> coefficients, const Result &shape, const QuantTables &tables, int qScale,
                std::vector<uint16_t> &out, const RateControl &rateControl = {});

// JPEG-style quality scaling of an MDEC(2) quant table. 1 is the coarsest and 100
// the finest; 50 returns the input unchanged. Entries clamp to 1..255, the width
// of the field the command carries.
//
// This is the axis q_scale cannot reach. q_scale multiplies AC divisors only - the
// DC divisor is qt[0] alone, matching the hardware, which ignores q_scale on the
// DC term - so scaling the table is the only way to trade DC precision, and it is
// the only way to change the SHAPE of quantization rather than its level.
void scaleQuantTable(const uint8_t *in, uint8_t *out, int quality);

// Map a quality percentage onto the MDEC's q_scale field. 100 is finest, 1 is
// coarsest, and the spread is geometric rather than linear because the format's
// own rate curve is: measured over the standard table, q_scale 1/8/16/32/63 give
// 90752/50304/33408/20480/12160 bytes on one 320x240 frame. A linear map puts the
// midpoint at q_scale 32, which is most of the way to the coarse end.
//
// quality 50 lands exactly on q_scale 8, which is the value every caller here
// defaulted to before there was a dial.
//
// ⚠ This deliberately moves q_scale ONLY and never the quant table. Scaling the
// standard table finer does not work: qt[0] is 2, the DC divisor is qt[0]*2, and
// the scale clamps at 1, so above about quality 50 the DC divisor pins at 2 and
// DC coefficients overrun the signed 10-bit run-level field - measured on both a
// high-frequency and a smooth 320x240 frame, mean error rising 1.31 -> 19.18 on
// the smooth one while the size barely moved. The standard table is not a default
// to be improved on, it is the finest DC the field tolerates. Over that table
// q_scale 1..63 is clip-free across its whole range, measured, and its error
// curve is monotonic.
int qualityToQScale(int quality);

// The standard MDEC quant table, the one every shipping encoder uses.
const uint8_t *standardQuantTable();

// What the run-level stream gets wrapped in for delivery. Everything upstream of
// here is shared; these differ only in what the PS1 has to do to get back to a
// run-level stream the MDEC can eat.
//
//   Bs   Sony's legacy BS: VLC/Huffman per the FileFormat47 code book, with the
//        8-byte header whose first word IS the MDEC decode command. Playable by
//        the stock library. Requires a single q_scale for the whole frame.
//   Raw  the run-level halfwords as bytes, padding included - exactly what DMA0
//        consumes. This is the handoff point for a compressing front end.
//
// ⛔ THERE IS DELIBERATELY NO Lz4 OR Ucl HERE, and it is a licensing boundary
// rather than a missing feature. ucl's compressor is GPLv2 while this library is
// MIT, so linking it would encumber every downstream user of supportpsx. The CLI
// compresses `Raw` and carries that licence itself. An enum value that always
// failed would be worse than its absence: it compiles, so the constraint would
// only show up at runtime.
enum class Container { Bs, Raw };

struct ContainerResult {
    bool failed = false;
    // Set whenever failed. A static string, safe to print, says WHICH constraint
    // was violated - "q_scale varies" and "stream is truncated" are different bugs
    // and a bare false cannot tell them apart.
    const char *error = nullptr;
    uint32_t bytes = 0;
    // 32-bit words of decompressed run-level, padding included. This is what BS's
    // header carries, because that field is literally the MDEC command's length.
    uint32_t rlWords = 0;
    uint32_t blocks = 0;
    int qScale = 0;  // the single q_scale, when the stream has one
};

// Wrap a packed run-level stream. `rl` is exactly what pack() produced.
ContainerResult toContainer(std::span<const uint16_t> rl, Container container, std::vector<uint8_t> &out);

// Exposed for testing: transform one 8x8 block in place, block-major, scalar,
// against the given basis, using the given variant's arithmetic. This is the
// reference every lane of that variant must match bit for bit.
void transformBlockReference(int16_t *block, const Basis &basis, Transform transform = Transform::ExactMatrix);

}  // namespace DCT

}  // namespace PCSX
