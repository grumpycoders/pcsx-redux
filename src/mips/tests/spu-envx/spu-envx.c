/*
 * Voice current ADSR volume (ENVX, 1F801C0Ch+N*10h) hardware characterisation.
 *
 * The ADSR trace harness spins unbounded on this register in two places - once
 * waiting for it to drain to zero before arming an envelope, once waiting for
 * it to leave zero after key-on. Neither spin has any evidence behind it, and
 * psx-spx says outright that whether release ends at zero may depend on an end
 * flag in the sample data. On silicon the harness hangs. So measure the
 * register first, then rebuild the harness on what it actually does.
 *
 * Questions, in the order the cases answer them:
 *   1. does a linear release reach EXACTLY zero, and how fast          (cases 1,2)
 *   2. does an EXPONENTIAL release reach zero at all                   (cases 3,4)
 *   3. does the sample-data end flag mute the envelope by itself       (cases 5,6)
 *   4. can a slow release be overridden mid-flight to drain quickly    (case 7)
 *
 * Everything is bounded. The tick is one SPUSTAT bit-11 edge pair, i.e. 256
 * output samples, 5.805 ms; every wait carries a tick cap and every case
 * reports how many it actually spent, so a case that never terminates reports
 * that as a result instead of taking the console with it.
 *
 * Case 1 is the negative control: a shift-0 linear release is the fastest the
 * hardware offers and must reach zero within a tick or two. If it does not,
 * the instrument is broken and no other line here means anything.
 * Case 6 is the control for the end-flag question: a looping sample must hold
 * its envelope for the whole window, so a case-5 mute is the END FLAG rather
 * than voices going quiet on their own.
 */

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/pcsxhw.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

#include <stdint.h>

#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)
#define SPU_ENDX_LOW (*(volatile uint16_t *)0x1f801d9c)
#define SPU_UPLOAD_ADDR 0x1080u

/* Packed 32-bit envelope, same field layout as the ADSR register pair. */
#define ATTACK(step, shift, exp) ((((step) & 3) << 8) | (((shift) & 31) << 10) | (!!(exp) << 15))
#define DECAY(shift) (((shift) & 15) << 4)
#define SUSTAIN(step, shift, level, direction, exp)                                       \
    ((((step) & 3) << 22) | (((shift) & 31) << 24) | (((level) & 15) << 0) |              \
     (!!(direction) << 30) | (!!(exp) << 31))
#define RELEASE(shift, exp) ((((shift) & 31) << 16) | (!!(exp) << 21))

/* Instant attack to full, no decay, sustain pinned at the top. Every case below
   starts from a known 0x7fff so the only variable is what happens after. */
#define HOLD_AT_PEAK (ATTACK(0, 0, 0) | DECAY(0) | SUSTAIN(3, 0, 15, 0, 0))

#define MAX_TICKS 512   /* 512 * 5.805ms = 2.97s per bounded wait */
#define TRACE_LEN 16

static const uint8_t kAdpcmSine[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x03, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
};

/* A tick is 256 output samples. A one-shot sine at rate 0x1000 lives for 112
   samples, so its whole existence fits inside one tick and a tick-sampled trace
   can only ever show the aftermath. The fine trace samples ~32 times across a
   tick instead, which resolves the attack onset and the end-flag mute. */
#define FINE_LEN 32
#define FINE_SPACING 2000 /* volatile loop iterations, ~3 cycles each */

static uint8_t s_upload[128] __attribute__((aligned(4)));
static uint16_t s_trace[TRACE_LEN];
static uint16_t s_fine[FINE_LEN];

static void spu_dma_write(uint32_t spuByteAddr, const void *src, uint32_t bytes) {
    const uint16_t tsa = (uint16_t)(spuByteAddr >> 3);
    SPU_RAM_DTA = tsa;
    for (int i = 0; i < 0xF01 && (SPU_RAM_DTA & 0xffff) != tsa; i++);
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x0020;
    for (volatile int i = 0; i < 60; i++);
    for (int i = 0; i < 0xF01 && (SPU_STATUS & 0x30) != 0x0020; i++);
    SPU_DELAY = (SPU_DELAY & 0xf0ffffff) | 0x20000000;
    uint32_t blocks = (bytes >> 6) + ((bytes & 0x3f) ? 1 : 0);
    DMA_CTRL[DMA_SPU].MADR = (uint32_t)src & 0x1fffffff;
    DMA_CTRL[DMA_SPU].BCR = (blocks << 16) | 0x10;
    DMA_CTRL[DMA_SPU].CHCR = 0x01000201;
    for (int i = 0; i < 0x100000 && (DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0; i++);
    SPU_CTRL = (SPU_CTRL & ~0x0030);
    for (volatile int i = 0; i < 60; i++);
}

/* One tick, bounded on both halves. Returns 0 if SPUSTAT never moved, which
   would mean the SPU is not running and every tick count below is fiction. */
static int spu_tick(void) {
    int n = 0;
    while (!(SPU_STATUS & 0x0800)) {
        if (++n > 2000000) return 0;
    }
    while ((SPU_STATUS & 0x0800)) {
        if (++n > 2000000) return 0;
    }
    return 1;
}

static void upload_sample(int oneShot) {
    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    /* Last block's flag byte: 0x03 is end+repeat (loops forever), 0x01 is end
       without repeat, which is the case psx-spx suspects mutes the envelope. */
    s_upload[3 * 16 + 1] = oneShot ? 0x01 : 0x03;
    spu_dma_write(SPU_UPLOAD_ADDR, s_upload, 128);
}

static void arm_voice(uint32_t adsr) {
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].volumeLeft = 0;
    SPU_VOICES[1].volumeRight = 0;
    SPU_VOICES[1].adsrLo = (uint16_t)(adsr & 0xffff);
    SPU_VOICES[1].adsrHi = (uint16_t)(adsr >> 16);
}

static void print_trace(const char *tag) {
    ramsyscall_printf("OBS %s trace", tag);
    for (int i = 0; i < TRACE_LEN; i++) ramsyscall_printf(" %04x", s_trace[i]);
    ramsyscall_printf("\n");
}

/*
 * One case. Keys the voice on, holds it briefly so the envelope is provably at
 * peak, then either keys off or lets the sample run out, and watches ENVX until
 * it hits zero or the tick cap expires.
 *
 *   keyOff      key the voice off after the hold (0 = let the sample decide)
 *   overrideRel if non-zero, this adsrHi is written one tick INTO the release,
 *               to test whether a slow release can be cut short mid-flight
 */
static void run_case(const char *tag, uint32_t adsr, int oneShot, int keyOff,
                     int overrideRel, uint16_t overrideHi) {
    SPU_CTRL = 0x8000;
    for (volatile int i = 0; i < 60; i++);
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    upload_sample(oneShot);
    SPU_CTRL = 0x8000 | 0x4000;
    for (volatile int i = 0; i < 60; i++);

    /* Drain whatever the previous case left, with a fast linear release so the
       drain itself can never be the thing that hangs. Bounded regardless. */
    SPU_VOICES[1].adsrHi = (uint16_t)(RELEASE(0, 0) >> 16);
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    int drain = 0;
    while (drain < MAX_TICKS && (SPU_VOICES[1].currentVolume & 0xffff) != 0) {
        if (!spu_tick()) break;
        drain++;
    }
    const uint16_t preKeyOn = SPU_VOICES[1].currentVolume & 0xffff;

    arm_voice(adsr);
    SPU_KEY_OFF_LOW = 0;
    SPU_KEY_OFF_HIGH = 0;
    SPU_KEY_ON_LOW = 1u << 1;
    SPU_KEY_ON_HIGH = 0;

    /* Sub-tick trace, taken first because everything it can see is over before
       the first tick boundary arrives. */
    for (int i = 0; i < FINE_LEN; i++) {
        s_fine[i] = SPU_VOICES[1].currentVolume & 0xffff;
        for (volatile int j = 0; j < FINE_SPACING; j++);
    }

    /* How long after key-on does ENVX leave zero. The harness spins unbounded
       on exactly this, so the number matters on its own. */
    int onset = 0;
    while (onset < MAX_TICKS && (SPU_VOICES[1].currentVolume & 0xffff) == 0) {
        if (!spu_tick()) break;
        onset++;
    }
    const uint16_t atOnset = SPU_VOICES[1].currentVolume & 0xffff;

    /* Hold four ticks so the peak is observed rather than assumed. */
    for (int i = 0; i < 4; i++) spu_tick();
    const uint16_t atPeak = SPU_VOICES[1].currentVolume & 0xffff;

    if (keyOff) {
        SPU_KEY_OFF_LOW = 1u << 1;
        SPU_KEY_OFF_HIGH = 0;
    }

    for (int i = 0; i < TRACE_LEN; i++) s_trace[i] = 0xffff;
    int ticks = 0;
    int zeroAt = -1;
    while (ticks < MAX_TICKS) {
        const uint16_t v = SPU_VOICES[1].currentVolume & 0xffff;
        if (ticks < TRACE_LEN) s_trace[ticks] = v;
        if (v == 0) {
            zeroAt = ticks;
            break;
        }
        if (overrideRel && ticks == 1) SPU_VOICES[1].adsrHi = overrideHi;
        if (!spu_tick()) break;
        ticks++;
    }
    const uint16_t finalV = SPU_VOICES[1].currentVolume & 0xffff;

    ramsyscall_printf(
        "OBS %s adsr=%08x oneshot=%d keyoff=%d drain=%d onset=%d envxAtOnset=%04x peak=%04x "
        "zeroAt=%d final=%04x endx=%d preKeyOn=%04x\n",
        tag, adsr, oneShot, keyOff, drain, onset, atOnset, atPeak, zeroAt, finalV,
        (SPU_ENDX_LOW & 2) ? 1 : 0, preKeyOn);
    ramsyscall_printf("OBS %s fine", tag);
    for (int i = 0; i < FINE_LEN; i++) ramsyscall_printf(" %04x", s_fine[i]);
    ramsyscall_printf("\n");
    print_trace(tag);

    SPU_VOICES[1].adsrHi = (uint16_t)(RELEASE(0, 0) >> 16);
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
}

int main() {
    ramsyscall_printf("OBS envx-probe start ticks=%d trace=%d\n", MAX_TICKS, TRACE_LEN);

    SPU_CTRL = 0;
    for (volatile int i = 0; i < 60; i++);
    SPU_RAM_DTC = 4;  /* required on real hardware for SPU RAM transfers */
    for (volatile int i = 0; i < 60; i++);
    DPCR |= 0x000b0000;
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_REVERB_LEFT = 0;
    SPU_REVERB_RIGHT = 0;
    SPU_PITCH_MOD_LOW = 0;
    SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0;
    SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0;
    SPU_REVERB_EN_HIGH = 0;
    SPU_REVERB_ADDR = 0xffff;
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;

    /* 1. NEGATIVE CONTROL. Fastest release the hardware has. If this does not
          reach zero almost immediately, the instrument is wrong. */
    run_case("rel_lin_s00", HOLD_AT_PEAK | RELEASE(0, 0), 0, 1, 0, 0);

    /* 2. A linear release slow enough to watch. Does it land on exactly zero,
          or stop one step short. */
    run_case("rel_lin_s12", HOLD_AT_PEAK | RELEASE(12, 0), 0, 1, 0, 0);

    /* 3. Exponential release. The suspect: a multiplicative decrease has ever
          smaller steps as the envelope falls, so it may asymptote. */
    run_case("rel_exp_s12", HOLD_AT_PEAK | RELEASE(12, 1), 0, 1, 0, 0);

    /* 4. Exponential release, shift 31. This is the exact envelope the capture
          helper leaves in the voice (adsrHi=0x80ff), which is what the trace
          harness then keys off and waits on. */
    run_case("rel_exp_s31", HOLD_AT_PEAK | RELEASE(31, 1), 0, 1, 0, 0);

    /* 5. THE END FLAG. Sample ends without repeat and the voice is never keyed
          off. If ENVX drops on its own, the end flag mutes the envelope. */
    run_case("endflag_oneshot", HOLD_AT_PEAK | RELEASE(31, 1), 1, 0, 0, 0);

    /* 6. CONTROL for case 5: same envelope, looping sample, no key off. This
          must hold at peak for the whole window. */
    run_case("endflag_looping", HOLD_AT_PEAK | RELEASE(31, 1), 0, 0, 0, 0);

    /* 7. Can a slow release be cut short by rewriting the release field while
          it is already in progress. This is the drain the harness needs. */
    run_case("rel_override", HOLD_AT_PEAK | RELEASE(31, 1), 0, 1, 1,
             (uint16_t)(RELEASE(0, 0) >> 16));

    ramsyscall_printf("OBS envx-probe done\n");
    pcsx_exit(0);
    return 0;
}
