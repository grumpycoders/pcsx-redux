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

uint16_t s_pixels[kMaxWidth * kMaxHeight] __attribute__((aligned(4)));
uint16_t s_rl[kMaxRl] __attribute__((aligned(4)));
uint8_t s_quant[128] __attribute__((aligned(4)));
int16_t s_scale[64] __attribute__((aligned(4)));

int waitDma(int ch) {
    for (unsigned i = 0; i < 20000000; i++) {
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

    bool decodeInto(uint32_t index);

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
    MDEC1 = 0x80000000;
    MDEC1 = 0x60000000;

    MDEC0 = MDEC_CMD_QUANT | 1;  // bit0 = colour, so 128 bytes follow
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)s_quant;
    DMA_CTRL[DMA_MDECIN].BCR = 32 << 16 | 1;
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
    waitDma(DMA_MDECIN);

    MDEC0 = MDEC_CMD_SCALE;
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)s_scale;
    DMA_CTRL[DMA_MDECIN].BCR = 32 << 16 | 1;
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
    waitDma(DMA_MDECIN);

    m_index = 0;
    m_shownAt = 0;
    m_haveFrame = false;
#ifdef MDECPLAYER_PROFILE
    COUNTERS[1].mode = 0x0100;  // hblank source, free running
#endif
}

bool PlayScene::decodeInto(uint32_t index) {
    const uint16_t tBs = PROF_HB();
    const BsdecResult r = bsdecFrame(m_hdr.frame(index), m_hdr.frameBytes(index), s_rl, kMaxRl);
    PROF_ACC(tBs, m_bsHb);
    if (!bsdecUsable(r.error)) return false;
    const uint16_t tMdec = PROF_HB();

    const uint32_t outWords = (m_hdr.width() * m_hdr.height() * 2) / 4;
    const uint32_t inWords = (r.halfwords + 1) / 2;

    MDEC0 = r.mdecCommand;  // word 0 of the BS header IS the decode command
    if (waitDma(DMA_MDECIN) < 0 || waitDma(DMA_MDECOUT) < 0) return false;

    // Both transfers are started before either is waited on. Once the MDEC has a
    // block ready it stops asserting Data-In Request, so DMA0 never completes
    // until DMA1 drains it - serialising them deadlocks on real silicon while
    // passing in the emulator, whose dma0 runs the pending dma1 for you.
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)s_rl;
    DMA_CTRL[DMA_MDECIN].BCR = 32 << 16 | ((inWords + 31) / 32);
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
    DMA_CTRL[DMA_MDECOUT].MADR = (uintptr_t)s_pixels;
    DMA_CTRL[DMA_MDECOUT].BCR = 32 << 16 | (outWords / 32);
    DMA_CTRL[DMA_MDECOUT].CHCR = 0x01000200;
    if (waitDma(DMA_MDECOUT) < 0 || waitDma(DMA_MDECIN) < 0) return false;
    PROF_ACC(tMdec, m_mdecHb);
    return true;
}

void PlayScene::frame() {
    if (m_broken) {
        gpu().clear({{.r = 0x60, .g = 0x00, .b = 0x00}});
        return;
    }

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
    if (!m_haveFrame || (now - m_shownAt) >= m_hdr.vsyncsPerFrame()) {
        const uint16_t t0 = PROF_HB();
        if (!decodeInto(m_index)) {
            m_broken = true;
            return;
        }
        PROF_ACC(t0, m_decHb);
#ifdef MDECPLAYER_PROFILE
        m_decodes++;
#endif
        m_shownAt = now;
        m_haveFrame = true;
        if (++m_index >= m_hdr.frames()) m_index = 0;  // loop
    }

    // The MDEC emits 16x16 macroblocks back to back, so each one is its own upload
    // region and no CPU reorder pass is needed. The order the macroblocks arrive in
    // is the stream's, not an assumption: raster walks rows, column-major walks
    // 16-pixel columns top to bottom, which is what retail STR does.
    const unsigned cols = m_hdr.width() / 16;
    const unsigned rows = m_hdr.height() / 16;
    const int16_t bufY = gpu().getParity() ? 256 : 0;
    const uint16_t *src = s_pixels;
    const uint16_t tUp = PROF_HB();
    for (unsigned i = 0; i < cols * rows; i++, src += 16 * 16) {
        const unsigned col = m_hdr.columnMajor() ? (i / rows) : (i % cols);
        const unsigned row = m_hdr.columnMajor() ? (i % rows) : (i / cols);
        psyqo::Rect region = {.pos = {{.x = int16_t(col * 16), .y = int16_t(bufY + row * 16)}},
                              .size = {{.w = 16, .h = 16}}};
        gpu().uploadToVRAM(src, region);
    }
    PROF_ACC(tUp, m_upHb);

#ifdef MDECPLAYER_PROFILE
    m_calls++;
    if (m_decodes >= 30) {
        // vsyncs per decoded frame is the number that answers "is it keeping up":
        // the blob asks for m_hdr.vsyncsPerFrame(), anything above that is the
        // shortfall, and it is measured in the guest so a slow host cannot fake it.
        const uint32_t vsyncs = now - m_reportAt;
        ramsyscall_printf(
            "MDPL: %d decodes over %d vsyncs (%d frame() calls), want %d vsync/frame, got %d.%02d\n", m_decodes,
            vsyncs, m_calls, m_hdr.vsyncsPerFrame(), vsyncs / m_decodes, (vsyncs * 100 / m_decodes) % 100);
        ramsyscall_printf("MDPL: hblanks/frame: bsdec %d + mdec %d (= decode %d) + upload %d, %d macroblocks\n",
                          m_bsHb / m_decodes, m_mdecHb / m_decodes, m_decHb / m_decodes, m_upHb / m_calls,
                          cols * rows);
        m_bsHb = m_mdecHb = m_decHb = m_upHb = m_decodes = m_calls = 0;
        m_reportAt = now;
    }
#endif
}

}  // namespace

int main() { return g_player.run(); }
