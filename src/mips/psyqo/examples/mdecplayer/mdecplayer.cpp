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

// A looping MDEC video player. The stream is linked in by stream.s, built from a
// PNG series by packstream.py, and is not in the repo.
//
// Everything that could disagree between the stream and the player travels in
// the blob header: macroblock order, the quantization table, the IDCT matrix,
// the frame rate and how many vsyncs one frame is worth. Nothing about the video
// is hard-coded here, which is the point - a player that disagrees with its
// stream about macroblock order renders as bands of vertically-striped blocks
// and looks like a decoder bug.
//
// 25 fps against PAL's 50 Hz and 30 fps against NTSC's 60 Hz both come out at two
// vsyncs per frame, which is why those two series pair with those two modes.

#include <stdint.h>

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "psyqo/application.hh"
#include "psyqo/gpu.hh"
#include "psyqo/kernel.hh"
#include "psyqo/primitives/common.hh"
#include "psyqo/scene.hh"

extern "C" {
#include "bsdec/bsdec.h"
}

// Build with -DMDECPLAYER_CAPTURE=n to decode frame n, hand the MDEC's own output
// back over pcdrv and exit, instead of playing. That is how the console path gets
// LOOKED at: the host side reassembles the macroblocks and diffs the result
// against the source PNG, so the capture covers bsdec on this CPU, the real MDEC,
// and the macroblock order all at once.
#ifdef MDECPLAYER_CAPTURE
extern "C" {
#include "common/hardware/pcsxhw.h"
#include "common/kernel/pcdrv.h"
#include "common/syscalls/syscalls.h"
}
#endif

// Build with -DMDECPLAYER_PROFILE to print where a frame's time goes. Counter 1
// free-runs on hblanks, so the unit is host-independent: one NTSC vsync is about
// 262 hblanks and one PAL vsync about 312, and a 16-bit hblank counter wraps
// every ~4 s, which is long enough that a per-phase delta never aliases.
#ifdef MDECPLAYER_PROFILE
// PROFILE=N reports every N decoded frames.
#if MDECPLAYER_PROFILE < 1
#undef MDECPLAYER_PROFILE
#define MDECPLAYER_PROFILE 30
#endif
#include "common/hardware/counters.h"
extern "C" {
#include "common/syscalls/syscalls.h"
}
#define PROF_HB() (COUNTERS[1].value)
#define PROF_ACC(start, acc) (acc) += (uint16_t)(COUNTERS[1].value - (start))
#else
#define PROF_HB() 0
#define PROF_ACC(start, acc) ((void)0)
#endif

#define MDEC0 HW_U32(0x1f801820)
#define MDEC1 HW_U32(0x1f801824)

#define MDEC_CMD_DECODE 0x30000000
#define MDEC_CMD_QUANT 0x40000000
#define MDEC_CMD_SCALE 0x60000000

// stream.s
extern "C" const uint8_t g_stream[];

namespace {

// Blob layout, little endian. packstream.py owns the writer; this owns the reader
// and validates every field it uses.
struct Header {
    static constexpr uint32_t kMagic = 0x4c50444d;  // 'MDPL'
    static constexpr uint32_t kOffsets = 0x118;

    const uint8_t *base;

    uint32_t u32(unsigned off) const {
        return (uint32_t)base[off] | ((uint32_t)base[off + 1] << 8) | ((uint32_t)base[off + 2] << 16) |
               ((uint32_t)base[off + 3] << 24);
    }
    uint32_t u16(unsigned off) const { return (uint32_t)base[off] | ((uint32_t)base[off + 1] << 8); }

    uint32_t magic() const { return u32(0x00); }
    uint32_t version() const { return u16(0x04); }
    uint32_t frames() const { return u16(0x06); }
    uint32_t width() const { return u16(0x08); }
    uint32_t height() const { return u16(0x0a); }
    uint32_t fps() const { return base[0x0c]; }
    bool columnMajor() const { return base[0x0d] != 0; }
    bool pal() const { return base[0x0e] != 0; }
    uint32_t vsyncsPerFrame() const { return base[0x0f]; }
    uint32_t maxRlHalfwords() const { return u32(0x10); }
    uint32_t maxFrameBytes() const { return u32(0x14); }
    const uint8_t *quant() const { return base + 0x18; }   // 128 bytes, Y then UV
    const int16_t *scale() const { return (const int16_t *)(base + 0x98); }
    const uint8_t *frame(uint32_t i) const { return base + u32(kOffsets + 4 * i); }
    uint32_t frameBytes(uint32_t i) const {
        const uint32_t here = u32(kOffsets + 4 * i);
        const uint32_t next = (i + 1 < frames()) ? u32(kOffsets + 4 * (i + 1)) : 0;
        return next ? next - here : maxFrameBytes();
    }
};

// 320x240 at 15bpp, which is what the magic 0x3800 in every BS header asks the
// MDEC for. Sized from the constants below and checked against the blob.
constexpr unsigned kMaxWidth = 320;
constexpr unsigned kMaxHeight = 240;
constexpr unsigned kMaxRl = 24576;  // blob says 16768 for q_scale 4 at this size

// Two frame buffers: the GPU uploads one while the MDEC fills the other. 150 KB
// each, which is what buys the overlap.
uint16_t s_pixels[2][kMaxWidth * kMaxHeight] __attribute__((aligned(4)));
uint16_t s_rl[kMaxRl] __attribute__((aligned(4)));
uint8_t s_quant[128] __attribute__((aligned(4)));
int16_t s_scale[64] __attribute__((aligned(4)));

// Overridable so the give-up path can be exercised on purpose: a diagnostic that
// only runs when something is stuck is otherwise never tested until it matters.
#ifndef MDECPLAYER_DMA_SPIN
#define MDECPLAYER_DMA_SPIN 20000000
#endif

// The table uploads are tiny and must always be allowed to finish, so they do not
// use the DMASPIN-shortened wait that exists to exercise the give-up path.
int waitDmaRaw(int ch) {
    for (unsigned i = 0; i < 20000000; i++) {
        if ((DMA_CTRL[ch].CHCR & 0x01000000) == 0) return 0;
    }
    return -1;
}

// Reset the MDEC and re-seat both tables. This runs before EVERY frame, not just
// at startup, because a decode that ends with input still queued leaves the
// command half-consumed: the next MDEC0 write lands on a busy command and the
// following frame wedges with the out-FIFO empty and DMA0 armed but idle.
// Measured on an SCPH-1001 (ticket 1175ab76): cancelling DMA0 alone got two
// frames out and then hung on the third. The two table uploads are 32 words
// each, which is noise next to a frame.
int mdecReset() {
    int bad = 0;
    MDEC1 = 0x80000000;  // abort whatever the last command left behind
    MDEC1 = 0x60000000;  // re-enable the data-in and data-out requests

    MDEC0 = MDEC_CMD_QUANT | 1;  // bit0 = colour, so 128 bytes follow
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)s_quant;
    DMA_CTRL[DMA_MDECIN].BCR = 32 << 16 | 1;
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
    if (waitDmaRaw(DMA_MDECIN) < 0) bad |= 1;

    MDEC0 = MDEC_CMD_SCALE;
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)s_scale;
    DMA_CTRL[DMA_MDECIN].BCR = 32 << 16 | 1;
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
    if (waitDmaRaw(DMA_MDECIN) < 0) bad |= 2;
    return bad;
}

int waitDma(int ch) {
    for (unsigned i = 0; i < MDECPLAYER_DMA_SPIN; i++) {
        if ((DMA_CTRL[ch].CHCR & 0x01000000) == 0) return 0;
    }
    return -1;
}

class Player final : public psyqo::Application {
    void prepare() override;
    void createScene() override;
};

class PlayScene final : public psyqo::Scene {
    void start(Scene::StartReason reason) override;
    void frame() override;

    bool decodeInto(uint32_t index, unsigned buf);
    void startUpload(unsigned buf);
    void uploadNext();
    void waitUpload();

    Header m_hdr{g_stream};
    uint32_t m_index = 0;
    uint32_t m_shownAt = 0;
    bool m_haveFrame = false;
    bool m_broken = false;
#ifdef MDECPLAYER_PROFILE
    uint32_t m_bsHb = 0;      // hblanks inside bsdecFrame alone, CPU side
    uint32_t m_mdecHb = 0;    // hblanks inside the MDEC command plus both DMAs
    uint32_t m_decHb = 0;     // hblanks inside decodeInto
    uint32_t m_upHb = 0;      // hblanks inside the macroblock upload loop
    uint32_t m_decodes = 0;   // frames actually decoded since the last report
    uint32_t m_calls = 0;     // frame() entries since the last report
    uint32_t m_reportAt = 0;  // gpu frame count at the last report
    uint32_t m_trace = 0;     // milestone prints remaining, for the first frames
    int m_lastErr = 0;        // bsdec error, or -1/-2 for a DMA that never finished
#endif
    bool m_needReset = false; // the last decode left the MDEC mid-command
    int m_resetBad = 0;       // what the last re-seat reported, for the -1 dump
    unsigned m_showBuf = 0;   // being uploaded to VRAM
    unsigned m_fillBuf = 1;   // being written by the MDEC
    unsigned m_upIndex = 0;   // next region in the running upload chain
    unsigned m_upCount = 0;   // regions in one frame
    int16_t m_upBufY = 0;     // VRAM half the chain is writing
    volatile bool m_upDone = true;
#ifdef MDECPLAYER_PROFILE
#endif
};

Player g_player;
PlayScene g_scene;

void Player::prepare() {
    const Header h{g_stream};
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(h.pal() ? psyqo::GPU::VideoMode::PAL : psyqo::GPU::VideoMode::NTSC)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Player::createScene() { pushScene(&g_scene); }

void PlayScene::start(Scene::StartReason) {
    // Refuse rather than play something that is not this format, or that does not
    // fit: a player that quietly renders a wrong-sized frame looks like a decoder
    // fault, which is the expensive way to find out.
    if (m_hdr.magic() != Header::kMagic || m_hdr.version() != 1 || m_hdr.frames() == 0 ||
        m_hdr.width() > kMaxWidth || m_hdr.height() > kMaxHeight || m_hdr.maxRlHalfwords() > kMaxRl ||
        m_hdr.vsyncsPerFrame() == 0) {
        m_broken = true;
        return;
    }

    for (unsigned i = 0; i < 128; i++) s_quant[i] = m_hdr.quant()[i];
    for (unsigned i = 0; i < 64; i++) s_scale[i] = m_hdr.scale()[i];

    DPCR |= 0x000000ff;  // the enable is bit 3 of each channel's nibble
    mdecReset();

    // Prime the pipeline: frame 0 is decoded here so that the very first frame()
    // already has something to upload while it decodes frame 1.
    m_index = 0;
    m_shownAt = 0;
    m_haveFrame = false;
    m_showBuf = 0;
    m_fillBuf = 1;
    m_upDone = true;
    if (!decodeInto(0, 0)) {
        m_broken = true;
        return;
    }
    m_haveFrame = true;
    m_index = 1 < m_hdr.frames() ? 1 : 0;
#ifdef MDECPLAYER_PROFILE
    COUNTERS[1].mode = 0x0100;  // hblank source, free running
#ifdef BSDEC_PROFILE
    bsdecProfileReset();  // also arms counter 2 at system clock / 8
#endif
    m_trace = 2;
    ramsyscall_printf("MDPL: start ok, %d frames %dx%d, %d vsync/frame, %s order\n", m_hdr.frames(),
                      m_hdr.width(), m_hdr.height(), m_hdr.vsyncsPerFrame(),
                      m_hdr.columnMajor() ? "column" : "raster");
#endif
}

bool PlayScene::decodeInto(uint32_t index, unsigned buf) {
    uint16_t *const dst = s_pixels[buf];
    // Only when the previous frame left the command half-consumed. Resetting
    // unconditionally means resetting twice in a row on frame 0, right behind
    // start()'s own reset, and on an SCPH-1001 that makes the quant upload stall
    // two words in with MDEC1 a004001e (ticket 72a16984).
    // The re-seat does NOT happen here. It shares the bus with the upload chain
    // that is running right now, and on an SCPH-1001 with 20 column-sized
    // transfers in flight the quant upload stalls 29 words in (MDEC1 a004001d,
    // ticket f41e90ef). It runs in the quiet window after waitUpload instead.
    const int resetBad = m_resetBad;
    const uint16_t tBs = PROF_HB();
    const BsdecResult r = bsdecFrame(m_hdr.frame(index), m_hdr.frameBytes(index), s_rl, kMaxRl);
    PROF_ACC(tBs, m_bsHb);
    if (!bsdecUsable(r.error)) {
#ifdef MDECPLAYER_PROFILE
        m_lastErr = (int)r.error;
#endif
        return false;
    }
    const uint16_t tMdec = PROF_HB();

    const uint32_t outWords = (m_hdr.width() * m_hdr.height() * 2) / 4;
    const uint32_t inWords = (r.halfwords + 1) / 2;

    MDEC0 = r.mdecCommand;  // word 0 of the BS header IS the decode command
    if (waitDma(DMA_MDECIN) < 0 || waitDma(DMA_MDECOUT) < 0) {
#ifdef MDECPLAYER_PROFILE
        m_lastErr = -1;  // a channel was still busy before the transfers were armed
        ramsyscall_printf("MDPL: -1 at frame %d. reset bad=%d (1 quant, 2 scale)\n", index, resetBad);
        ramsyscall_printf("MDPL: MDEC1 %08x  ch0 CHCR %08x  ch1 CHCR %08x\n", MDEC1,
                          DMA_CTRL[DMA_MDECIN].CHCR, DMA_CTRL[DMA_MDECOUT].CHCR);
#else
        (void)resetBad;
#endif
        return false;
    }

#ifdef MDECPLAYER_PROFILE
    // Poison the destination so "how far did DMA1 actually get" is answerable by
    // looking at RAM rather than by guessing at BCR readback semantics. Only while
    // tracing: 76800 stores inside the timed region would otherwise BE the
    // measurement.
    if (m_trace) {
        for (uint32_t i = 0; i < m_hdr.width() * m_hdr.height(); i++) dst[i] = 0xdead;
    }
#endif

    // Both transfers are started before either is waited on. Once the MDEC has a
    // block ready it stops asserting Data-In Request, so DMA0 never completes
    // until DMA1 drains it - serialising them deadlocks on real silicon while
    // passing in the emulator, whose dma0 runs the pending dma1 for you.
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)s_rl;
    DMA_CTRL[DMA_MDECIN].BCR = 32 << 16 | ((inWords + 31) / 32);
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
    DMA_CTRL[DMA_MDECOUT].MADR = (uintptr_t)dst;
    DMA_CTRL[DMA_MDECOUT].BCR = 32 << 16 | (outWords / 32);
    DMA_CTRL[DMA_MDECOUT].CHCR = 0x01000200;
    // THE OUTPUT IS WHAT FINISHES A FRAME, NOT THE INPUT. bsdec pads the run-level
    // buffer out to a 32-word block and the BS header's word count covers the
    // padding, so the MDEC emits all 300 macroblocks and then stops consuming with
    // input still queued: in-FIFO full, Data-In Request deasserted, DMA0 busy
    // forever. Measured on an SCPH-1001 (ticket 84f931e0): DMA1 had landed 76800 of
    // 76800 halfwords while DMA0 sat at CHCR 01000201. Redux drains the tail for
    // you, which is why waiting on both passes there and hangs on silicon.
    // So: wait on the output, then cancel whatever input is left.
    if (waitDma(DMA_MDECOUT) < 0) {
#ifdef MDECPLAYER_PROFILE
        m_lastErr = -2;  // the decode transfers themselves never completed
        // Which side is stuck, and what the MDEC thinks, because "neither
        // finished" is one symptom over several different faults.
        ramsyscall_printf("MDPL: stuck. cmd %08x words %d (hdr %d) out %d\n", r.mdecCommand, inWords,
                          r.mdecCommand & 0xffff, outWords);
        ramsyscall_printf("MDPL: MDEC1 %08x  DPCR %08x  DICR %08x\n", MDEC1, DPCR, DICR);
        ramsyscall_printf("MDPL: ch0 CHCR %08x BCR %08x MADR %08x\n", DMA_CTRL[DMA_MDECIN].CHCR,
                          DMA_CTRL[DMA_MDECIN].BCR, DMA_CTRL[DMA_MDECIN].MADR);
        ramsyscall_printf("MDPL: ch1 CHCR %08x BCR %08x MADR %08x\n", DMA_CTRL[DMA_MDECOUT].CHCR,
                          DMA_CTRL[DMA_MDECOUT].BCR, DMA_CTRL[DMA_MDECOUT].MADR);
        // How many halfwords DMA1 actually landed, counted in RAM rather than
        // inferred from a register whose readback rules I would be guessing at.
        {
            const uint32_t total = m_hdr.width() * m_hdr.height();
            uint32_t written = 0, last = 0;
            for (uint32_t i = 0; i < total; i++) {
                if (dst[i] != 0xdead) {
                    written++;
                    last = i;
                }
            }
            ramsyscall_printf("MDPL: DMA1 landed %d of %d halfwords, last touched %d\n", written, total, last);
        }
#endif
        return false;
    }
    // The frame is done the moment the output lands. If the input never drained,
    // drop the tail and remember that the MDEC needs re-seating before the next
    // command; if it drained by itself there is nothing to clean up.
    if (DMA_CTRL[DMA_MDECIN].CHCR & 0x01000000) {
        DMA_CTRL[DMA_MDECIN].CHCR = 0;
        m_needReset = true;
    }
    PROF_ACC(tMdec, m_mdecHb);
#ifdef MDECPLAYER_PROFILE
    if (m_trace) {
        // Sum the decoded frame so the console and the emulator can be compared on
        // the pixels rather than on whether anything crashed.
        uint32_t sum = 0;
        for (uint32_t i = 0; i < m_hdr.width() * m_hdr.height(); i++) sum = sum * 31u + dst[i];
        ramsyscall_printf("MDPL: frame %d pixel sum %08x\n", index, sum);
    }
#endif
    return true;
}

// One region of the running chain. The MDEC emits 16x16 macroblocks back to back,
// so each is its own VRAM rect and no CPU reorder pass is needed. The order they
// arrive in is the stream's, not an assumption: raster walks rows, column-major
// walks 16-pixel columns top to bottom, which is what retail STR does.
void PlayScene::uploadNext() {
    if (m_upIndex >= m_upCount) {
        m_upDone = true;
        return;
    }
    const unsigned i = m_upIndex++;
    const unsigned cols = m_hdr.width() / 16;
    const unsigned rows = m_hdr.height() / 16;
    psyqo::Rect region;
    const uint16_t *src;
    if (m_hdr.columnMajor()) {
        // ⛔ UNREACHABLE TODAY AND DELIBERATELY KEPT. `mdec` emits raster order, and
        // packstream's --order flag DECLARES what the encoder emits rather than
        // reordering anything, so passing --order column writes a header byte that
        // lies about the data. Caught by the pixel sums coming back byte-identical
        // to the raster build, which they could not be if the order had changed.
        // A whole 16-wide column is ONE contiguous run: 15 macroblocks back to
        // back, each 16 rows of 16, which is exactly what a 16x240 VRAM rect
        // consumes. 20 transfers instead of 300, for the same bytes.
        region = {.pos = {{.x = int16_t(i * 16), .y = m_upBufY}},
                  .size = {{.w = 16, .h = int16_t(rows * 16)}}};
        src = s_pixels[m_showBuf] + i * rows * 16 * 16;
    } else {
        region = {.pos = {{.x = int16_t((i % cols) * 16), .y = int16_t(m_upBufY + (i / cols) * 16)}},
                  .size = {{.w = 16, .h = 16}}};
        src = s_pixels[m_showBuf] + i * 16 * 16;
    }
    gpu().uploadToVRAM(src, region, [this]() { uploadNext(); }, psyqo::DMA::FROM_ISR);
}

void PlayScene::startUpload(unsigned buf) {
    if (!m_haveFrame) return;  // nothing decoded yet, so nothing to show
    m_showBuf = buf;
    m_upBufY = gpu().getParity() ? 256 : 0;
    m_upCount = m_hdr.columnMajor() ? (m_hdr.width() / 16) : (m_hdr.width() / 16) * (m_hdr.height() / 16);
    m_upIndex = 0;
    m_upDone = false;
    uploadNext();
}

void PlayScene::waitUpload() {
    while (!m_upDone) psyqo::Kernel::Internal::pumpCallbacks();
}

void PlayScene::frame() {
    if (m_broken) {
#ifdef MDECPLAYER_PROFILE
        if (m_trace) {
            m_trace = 0;
            ramsyscall_printf("MDPL: BROKEN, last error %d (>=0 bsdec, -1 channel busy, -2 no completion)\n",
                              m_lastErr);
        }
#endif
        gpu().clear({{.r = 0x60, .g = 0x00, .b = 0x00}});
        return;
    }
#ifdef MDECPLAYER_PROFILE
    if (m_trace) ramsyscall_printf("MDPL: frame() entry, index %d\n", m_index);
#endif

#ifdef MDECPLAYER_CAPTURE
    {
        const uint32_t want = MDECPLAYER_CAPTURE;
        if (want >= m_hdr.frames()) {
            ramsyscall_printf("MDPL: capture frame %d but the stream has %d\n", want, m_hdr.frames());
            pcsx_exit(20);
        }
        for (uint32_t i = 0; i <= want; i++) {
            if (!decodeInto(i)) {
                ramsyscall_printf("MDPL: decode failed on frame %d\n", i);
                pcsx_exit(21);
            }
        }
        PCinit();
        const int fd = PCcreat("mdecplay.bin", 0);
        if (fd < 0) {
            ramsyscall_printf("MDPL: PCcreat failed\n");
            pcsx_exit(22);
        }
        uint8_t hdr[8];
        hdr[0] = (uint8_t)m_hdr.width();
        hdr[1] = (uint8_t)(m_hdr.width() >> 8);
        hdr[2] = (uint8_t)m_hdr.height();
        hdr[3] = (uint8_t)(m_hdr.height() >> 8);
        hdr[4] = m_hdr.columnMajor() ? 1 : 0;
        hdr[5] = (uint8_t)want;
        hdr[6] = (uint8_t)(want >> 8);
        hdr[7] = 0;
        const int bytes = (int)(m_hdr.width() * m_hdr.height() * 2);
        const int wh = PCwrite(fd, hdr, sizeof(hdr));
        const int wb = PCwrite(fd, s_pixels, bytes);
        PCclose(fd);
        if (wh != (int)sizeof(hdr) || wb != bytes) {
            ramsyscall_printf("MDPL: short write %d/%d and %d/%d\n", wh, (int)sizeof(hdr), wb, bytes);
            pcsx_exit(23);
        }
        ramsyscall_printf("MDPL: captured frame %d, %d bytes, %s order\nMDPL: end\n", want, bytes,
                          m_hdr.columnMajor() ? "column" : "raster");
        pcsx_exit(0);
    }
#endif

    const uint32_t now = gpu().getFrameCount();

    // THE WHOLE POINT OF THE DOUBLE BUFFER. The frame decoded last time goes to
    // VRAM asynchronously, and the CPU decodes the NEXT one into the other buffer
    // while the GPU DMA drains this one. Upload and decode used to be strictly
    // serial, which on an SCPH-1001 cost 580 of 1900 hblanks a frame doing nothing
    // but spinning on a DMA that needed no CPU at all.
    const uint16_t tUp = PROF_HB();
    startUpload(m_showBuf);

    const uint16_t t0 = PROF_HB();
    const bool ok = decodeInto(m_index, m_fillBuf);
    PROF_ACC(t0, m_decHb);

    // The GPU has to be finished before psyqo flips, so the wait lands here, after
    // the decode rather than instead of it. What it measures now is the OVERHANG:
    // upload time the decode did not already cover.
    waitUpload();
    PROF_ACC(tUp, m_upHb);

    // Nothing is on the bus now, so this is where the MDEC gets re-seated if the
    // decode above left its command half-consumed.
    if (m_needReset) {
        m_resetBad = mdecReset();
        m_needReset = false;
    } else {
        m_resetBad = 0;
    }

    if (!ok) {
        m_broken = true;
        return;
    }
#ifdef MDECPLAYER_PROFILE
    m_decodes++;
    if (m_trace) ramsyscall_printf("MDPL: decode %d ok into buf %d\n", m_index, m_fillBuf);
#endif
    m_shownAt = now;
    m_haveFrame = true;
    if (++m_index >= m_hdr.frames()) m_index = 0;  // loop

    const unsigned swap = m_showBuf;
    m_showBuf = m_fillBuf;
    m_fillBuf = swap;

    const unsigned cols = m_hdr.width() / 16;
    const unsigned rows = m_hdr.height() / 16;

#ifdef MDECPLAYER_PROFILE
    if (m_trace) {
        m_trace--;
        ramsyscall_printf("MDPL: upload pass done, %d macroblocks\n", cols * rows);
    }
    m_calls++;
    if (m_decodes >= MDECPLAYER_PROFILE) {
        // vsyncs per decoded frame is the number that answers "is it keeping up":
        // the blob asks for m_hdr.vsyncsPerFrame(), anything above that is the
        // shortfall, and it is measured in the guest so a slow host cannot fake it.
        const uint32_t vsyncs = now - m_reportAt;
        ramsyscall_printf(
            "MDPL: %d decodes over %d vsyncs (%d frame() calls), want %d vsync/frame, got %d.%02d\n", m_decodes,
            vsyncs, m_calls, m_hdr.vsyncsPerFrame(), vsyncs / m_decodes, (vsyncs * 100 / m_decodes) % 100);
        // The upload runs under the decode now, so its cost shows up two ways: the
        // ISR TAX is CPU time the chain's interrupts stole from the decode, and the
        // OVERHANG is upload time the decode did not manage to cover. Both are the
        // upload; neither is visible in a serial version.
        const uint32_t dec = m_decHb / m_decodes;
        const uint32_t work = m_bsHb / m_decodes + m_mdecHb / m_decodes;
        ramsyscall_printf("MDPL: hblanks/frame: bsdec %d + mdec %d + isr-tax %d = %d, overhang %d, %d regions\n",
                          m_bsHb / m_decodes, m_mdecHb / m_decodes, dec > work ? dec - work : 0, dec,
                          (m_upHb / m_calls) > dec ? (m_upHb / m_calls) - dec : 0, m_upCount);
#ifdef BSDEC_PROFILE
        {
            // Raw counters. One counter-2 tick is 8 system clocks, so ticks * 8
            // is cycles exactly; the division is left to whoever reads this.
            const BsdecProf *p = bsdecProfile();
            ramsyscall_printf("MDPL: bsdec ticks dc %d ac %d over %d blocks, %d ac symbols\n", p->tDc, p->tAc,
                              p->blocks, p->acSymbols);
            ramsyscall_printf("MDPL: bsdec work: %d refill calls, %d refill bytes, %d dc scan iters\n",
                              p->refillCalls, p->refillBytes, p->dcScanIters);
            bsdecProfileReset();
        }
#endif
        m_bsHb = m_mdecHb = m_decHb = m_upHb = m_decodes = m_calls = 0;
        m_reportAt = now;
    }
#endif
}

}  // namespace

int main() { return g_player.run(); }
