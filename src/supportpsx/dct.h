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

// 64 signed Q14 coefficients, row-major. Row i column k is the weight of input k
// in output i of a 1D 8-point transform.
using Basis = std::array<int16_t, 64>;

// The standard MDEC basis: cos(n*pi/16)/2 in Q14, the table every shipping game
// uploads.
const Basis &standardBasis();

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

// Coefficients are block-major: 64 int16 per block, blocks in MDEC order within
// each macroblock (Cr, Cb, Y1, Y2, Y3, Y4), macroblocks in raster order.
// Downstream can treat coefficients.data() + 64 * n as one 8x8 block.
//
// Note that the kernel works batch-major internally (one SIMD lane per block) and
// de-interleaves on store. If a downstream stage is also going to be vectorized,
// that de-interleave is pure waste and this is the place to add a batch-major
// accessor rather than transposing twice.
struct Result {
    std::vector<int16_t> coefficients;
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
    explicit Encoder(unsigned threads = 0, Basis basis = standardBasis());
    ~Encoder();

    Encoder(const Encoder &) = delete;
    Encoder &operator=(const Encoder &) = delete;

    // The frame's pixels are read on a worker thread at an unspecified later time.
    // The caller owns them and must keep them alive until the returned Promise has
    // been joined. Nothing is copied here.
    Promise submit(const Frame &frame);

    // Which kernel lane the runtime probe selected, for logs.
    const char *lane() const;

    unsigned threadCount() const { return m_threadCount; }

  private:
    struct Job {
        Frame frame;
        std::promise<Result> result;
    };

    void worker();

    Basis m_basis;
    std::array<int16_t, 64> m_basisQ15{};
    unsigned m_threadCount = 0;
    std::vector<std::thread> m_threads;
    std::deque<Job> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_shutdown = false;
    bool m_useAvx2 = false;
};

// Exposed for testing: transform one 8x8 block in place, block-major, scalar,
// against the given basis. This is the reference the vectorized lanes must match
// bit for bit.
void transformBlockReference(int16_t *block, const Basis &basis);

}  // namespace DCT

}  // namespace PCSX
