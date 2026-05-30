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

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/spu.h"
#include "common/kernel/pcdrv.h"
#include "common/syscalls/syscalls.h"
#include <stdint.h>

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

#ifndef SPU_TEST_HELPERS_DEFINED
#define SPU_TEST_HELPERS_DEFINED

#define INCLUDE_PCM(NAME) \
    asm( \
        ".pushsection .rodata\n" \
        ".global " #NAME "\n" \
        ".align 2\n" \
        #NAME ":\n" \
        ".incbin \"" #NAME ".test.pcm\"\n"\
        ".popsection"); \
    extern const uint8_t NAME[]

INCLUDE_PCM(silent);
INCLUDE_PCM(sine_low);
INCLUDE_PCM(sine);
INCLUDE_PCM(sine_high);
INCLUDE_PCM(sine_pitch_0800);
INCLUDE_PCM(sine_pitch_2000);
INCLUDE_PCM(sine_pitch_3000);
INCLUDE_PCM(triangle);
INCLUDE_PCM(square);
INCLUDE_PCM(loop_t0);
INCLUDE_PCM(loop_t1);

// ADPCM samples, each looping back to start with filter=0, shift=0,
// all sampled at 1575Hz unless otherwise specified.
static const uint8_t kAdpcmSilent[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t kAdpcmSine[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x03, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
};
static const uint8_t kAdpcmTriangle[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x32, 0x54, 0x76, 0x56, 0x34, 0x12, 0xe0, 0xcd, 0xab, 0x89, 0xa9, 0xcb, 0xed,
    0x00, 0x00, 0x10, 0x32, 0x54, 0x76, 0x56, 0x34, 0x12, 0xe0, 0xcd, 0xab, 0x89, 0xa9, 0xcb, 0xed,
    0x00, 0x00, 0x10, 0x32, 0x54, 0x76, 0x56, 0x34, 0x12, 0xe0, 0xcd, 0xab, 0x89, 0xa9, 0xcb, 0xed,
    0x00, 0x03, 0x10, 0x32, 0x54, 0x76, 0x56, 0x34, 0x12, 0xe0, 0xcd, 0xab, 0x89, 0xa9, 0xcb, 0xed,
};
static const uint8_t kAdpcmSquare[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x00, 0x00, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x00, 0x00, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x00, 0x03, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
};
static const uint8_t kAdpcmSine394Hz[64] __attribute__((aligned(4))) = { // low-pitch sine wave
    0x00, 0x06, 0x00, 0x10, 0x21, 0x32, 0x33, 0x44, 0x54, 0x55, 0x66, 0x76, 0x77, 0x77, 0x77, 0x77,
    0x00, 0x00, 0x77, 0x77, 0x77, 0x77, 0x77, 0x66, 0x56, 0x55, 0x44, 0x34, 0x33, 0x22, 0x11, 0x00,
    0x00, 0x00, 0xf0, 0xef, 0xde, 0xcd, 0xcc, 0xbb, 0xab, 0xaa, 0x99, 0x89, 0x88, 0x88, 0x88, 0x88,
    0x00, 0x03, 0x88, 0x88, 0x88, 0x88, 0x88, 0x99, 0xa9, 0xaa, 0xbb, 0xcb, 0xcc, 0xdd, 0xee, 0xff,
};
static const uint8_t kAdpcmSine5512Hz[64] __attribute__((aligned(4))) = { // high-pitch sine wave
    0x00, 0x06, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57,
    0x00, 0x00, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8,
    0x00, 0x00, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57,
    0x00, 0x03, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8, 0x50, 0x57, 0xa0, 0xa8,
};

typedef struct {
    uint32_t magic;   // 'PCMT' header magic code
    uint32_t length;  // size of this header, useful for versioning+expandability
    uint32_t warmup;  // ADPCM-decoded bytes with artifacts from a previous run
    uint32_t period;  // repeatable ADPCM-decoded bytes after warm-up
} PcmTestHeader;

// when defined, pcm test data is generated instead of testing it.
// useful for either creating new tests or for diff-ing failures.
#ifdef SPU_DUMP
static int is_pcdrv_init = 0;
static void spu_dump(const char *name, const void *buf, int len) {
    if (!is_pcdrv_init) {
        PCinit();
        is_pcdrv_init = 1;
    }
    int fd = PCcreat(name, 0);
    if (fd < 0) return;
    PCwrite(fd, buf, len);
    PCclose(fd);
}

static void spu_pcm_analyze(const uint8_t *data, uint32_t L,
                            uint32_t *out_warmup, uint32_t *out_period) {
    uint32_t best_kept = L, best_w = 0, best_p = L;
    for (uint32_t period = 2; period <= L / 2; period += 2) {
        uint32_t i = L - period;
        for (;;) {
            if (i < period) break;
            // Compare data[i-period .. i) against data[L-period .. L).
            int eq = 1;
            for (uint32_t k = 0; k < period; k++) {
                if (data[i - period + k] != data[L - period + k]) { eq = 0; break; }
            }
            if (!eq) break;
            i -= period;
        }
        uint32_t warmup = i;
        uint32_t kept = warmup + period;
        if (kept < best_kept) { best_kept = kept; best_w = warmup; best_p = period; }
    }
    *out_warmup = best_w;
    *out_period = best_p;
}
static void spu_dump_pcm(const char *name, const void *capture, uint32_t len) {
    static PcmTestHeader hdr = {0x544d4350u, sizeof(PcmTestHeader), 0, 0};
    spu_pcm_analyze((const uint8_t *)capture, len, &hdr.warmup, &hdr.period);
    if (!is_pcdrv_init) {
        PCinit();
        is_pcdrv_init = 1;
    }
    int fd = PCcreat(name, 0);
    if (fd < 0) return;
    PCwrite(fd, &hdr, sizeof(hdr));
    PCwrite(fd, capture, hdr.warmup + hdr.period);
    PCclose(fd);
}
#endif

// COM_DELAY at 0x1F801014. SDK programs upper nibble before every SPU DMA.
#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)
#define SPU_UPLOAD_ADDR 0x1080

static void spu_dma_sync(uint32_t spuByteAddr, uint32_t cpuAddr, uint32_t bytes,
                         int isRead) {
    const uint16_t tsa = (uint16_t)(spuByteAddr >> 3);
    const uint16_t modeBits = isRead ? 0x0030 : 0x0020;
    const uint32_t delay = isRead ? 0x22000000 : 0x20000000;
    const uint32_t chcr = isRead ? 0x01000200 : 0x01000201;

    SPU_RAM_DTA = tsa;
    for (int i = 0; i < 0xF01 && (SPU_RAM_DTA & 0xffff) != tsa; i++) ;
    SPU_CTRL = (SPU_CTRL & ~0x0030) | modeBits;
    for (volatile int i = 0; i < 60; i++) ;
    for (int i = 0; i < 0xF01 && (SPU_STATUS & 0x30) != modeBits; i++) ;
    SPU_DELAY = (SPU_DELAY & 0xf0ffffff) | delay;

    uint32_t blocks = (bytes >> 6) + ((bytes & 0x3f) ? 1 : 0);
    DMA_CTRL[DMA_SPU].MADR = cpuAddr & 0x1fffffff;
    DMA_CTRL[DMA_SPU].BCR = (blocks << 16) | 0x10;
    DMA_CTRL[DMA_SPU].CHCR = chcr;
    while ((DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0) __asm__ volatile("");

    SPU_CTRL = (SPU_CTRL & ~0x0030);
    for (volatile int i = 0; i < 60; i++) ;
}

static inline void spu_write_sync(uint32_t spuAddr, const void *src, uint32_t bytes) {
    spu_dma_sync(spuAddr, (uint32_t)src, bytes, 0);
}
static inline void spu_read_sync(uint32_t spuAddr, void *dst, uint32_t bytes) {
    spu_dma_sync(spuAddr, (uint32_t)dst, bytes, 1);
}

__attribute__((noinline))
static void spu_busy_wait(unsigned cycles) {
    // waste time on CPU, 3 cycles per loop
    unsigned n = cycles / 3;
    if (n == 0) return;
    __asm__ volatile (
        "1: addiu %0, %0, -1 \n"
        "   bnez  %0, 1b     \n"
        "   nop              \n"
        : "+r"(n) : : "memory"
    );
}

static inline void spu_wait_status_bit11_flip(void) {
    while (!(SPU_STATUS & 0x0800));
    while ((SPU_STATUS & 0x0800));
}

static void spu_reset_quiet(void) {
    DPCR |= 0x000b0000;
    SPU_CTRL = 0;
    SPU_VOL_MAIN_LEFT = 0; SPU_VOL_MAIN_RIGHT = 0;
    SPU_REVERB_LEFT = 0; SPU_REVERB_RIGHT = 0;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    SPU_PITCH_MOD_LOW = 0; SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0; SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0; SPU_REVERB_EN_HIGH = 0;
    // Push reverb work area to the very top of SPU RAM so its writes don't
    // overlap any test address.
    SPU_REVERB_ADDR = 0xffff;
    SPU_RAM_DTC = 4;
    SPU_CTRL = 0x8000;
}

// Configure voice 1 with envelope at peak from the very first sample so the
// capture mirror is the raw decoded waveform.
static void spu_voice1_keyon(uint32_t spuAddr, uint16_t pitch) {
    SPU_VOICES[1].sampleRate = pitch;
    SPU_VOICES[1].sampleStartAddr = spuAddr >> 3;
    SPU_VOICES[1].sampleRepeatAddr = spuAddr >> 3;
    SPU_VOICES[1].adsrLo = 0x000f;   // instant attack, sustain level=0xF
    SPU_VOICES[1].adsrHi = 0x1fc0;   // sustain rate=0x7F, increase, linear
    SPU_KEY_OFF_LOW = 0; SPU_KEY_OFF_HIGH = 0;
    SPU_KEY_ON_LOW = 1u << 1;
}

// Compare a captured waveform against a golden, tolerating the SPU's capture-
// start jitter. The bit-11 sync pins the start to within ~1 sample, landing on
// one of two adjacent boundaries (deterministic per power-on, and the boundary
// differs across PS1 revisions). The captured signal is otherwise bit-identical
// to the golden, so find the best-aligning integer-sample shift in a tiny window
// and then require an exact match at that shift. Samples are 16-bit.
#define SPU_GOLDEN_MAXSHIFT 2  // samples; observed jitter only ever lands in {-1,0,+1}
static int spu_compare_golden(const char *name, const void *cap,
                              const uint8_t *golden_file) {
    const PcmTestHeader *h = (const PcmTestHeader *)golden_file;
    const int16_t *golden = (const int16_t *)(golden_file + h->length);
    const int16_t *a = (const int16_t *)cap;
    const int warmupS = (int)(h->warmup / 2);
    const int periodS = (int)(h->period / 2);
    const int keptS = warmupS + periodS;

    int bestShift = 0, bestBad = 0x7fffffff;
    for (int s = -SPU_GOLDEN_MAXSHIFT; s <= SPU_GOLDEN_MAXSHIFT; s++) {
        int bad = 0;
        for (int i = 0; i < keptS; i++) {
            int j = i + s;
            if (j < 0 || j >= 512) continue;
            if (a[j] != golden[i]) bad++;
        }
        if (bad < bestBad) {
            bestBad = bad;
            bestShift = s;
        }
    }

    for (int i = 0; i < keptS; i++) {
        int j = i + bestShift;
        if (j < 0 || j >= 512) continue;
        if (a[j] != golden[i]) {
            ramsyscall_printf("%s mismatch at sample %d (shift %d): got 0x%04x, want 0x%04x\n",
                              name, i, bestShift, (uint16_t)a[j], (uint16_t)golden[i]);
            return i + 1;
        }
    }
    for (int i = keptS + SPU_GOLDEN_MAXSHIFT; i < 512; i++) {
        if (a[i] != a[i - periodS]) {
            ramsyscall_printf("%s periodicity broken at sample %d: got 0x%04x, want 0x%04x\n",
                              name, i, (uint16_t)a[i], (uint16_t)a[i - periodS]);
            return i + 1;
        }
    }
    return 0;
}

#ifdef SPU_DUMP
#define SPU_ASSERT_GOLDEN(name) spu_dump_pcm(#name ".test.pcm", s_capture, 1024)
#else
#define SPU_ASSERT_GOLDEN(name) \
    cester_assert_int_eq(0, spu_compare_golden(#name, s_capture, name))
#endif

#endif

// clang-format off

CESTER_BODY(
// All buffers in main RAM - the DMAC cannot target the CPU scratchpad.
static uint8_t  s_upload[64 + 64] __attribute__((aligned(4)));
static uint16_t s_capture[512]    __attribute__((aligned(4)));
static uint8_t  s_readback[4096]  __attribute__((aligned(4)));

// Deterministic voice1 capture being sampled at 44.1kHz in the SPU RAM.
// Reading at an arbitrary moment gives a phase-rotated snapshot that differs
// at every run. To get deterministic captures, this function will:
//   1. key off + drain so voice 1's capture region becomes all-zero
//   2. wait for SPUSTAT.bit11 to transition 1→0 for the capture to start
//   3. key on voice 1 immediately after the edge
//   4. wait for the next 1→0 edge for the full capture to complete for voice1
//   5. read the captured voice1 buffer ring via DMA
// The result is deterministic modulo at most 1 sample of jitter from the
// CPU spin vs SPU sample-clock granularity.
static void run_voice1_with_sample(const uint8_t *sample64, uint16_t pitch) {
    spu_reset_quiet();
    for (int i = 0; i < 64; i++) s_upload[i] = sample64[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_write_sync(SPU_UPLOAD_ADDR, s_upload, 128);
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;

    // Drain voice 1 capture ring to all-zero (~12 ms covers >1 full lap).
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    spu_busy_wait(800000);

    spu_wait_status_bit11_flip();
    spu_voice1_keyon(SPU_UPLOAD_ADDR, pitch);
    spu_wait_status_bit11_flip();

    spu_read_sync(0x0800, s_capture, 1024);
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    muteSpu();
}
)

CESTER_BODY(
static int s_interruptsWereEnabled;
)

// The bit-11 capture sync and the busy-wait-timed envelope reads are both
// jitter-sensitive: an interrupt (Unirom's SIO/timer/vblank handlers) firing
// mid-measurement perturbs the timing, mis-syncing a capture or pushing an
// envx read past its tolerance. Disable interrupts for the suite, as the
// cop0/cpu/timer tests do.
CESTER_BEFORE_ALL(spu_tests,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
)

CESTER_AFTER_ALL(spu_tests,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

#include "spu-transfer.c"
#include "spu-adpcm.c"
#include "spu-capture.c"
#include "spu-adsr.c"
