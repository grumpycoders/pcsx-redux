/*
 * What does silicon actually do for the sustain rates the suite gets wrong?
 *
 * On hardware the bounded suite fails `adsr_sustain_up_linear` and
 * `adsr_sustain_down_linear`, and in both cases ONLY the final block - sustain
 * shift 16, step 0, linear, one in each direction. Every other block in both
 * tests passes, including shift 14 immediately above it. The failing asserts
 * use ASSERT_ENVX_NEAR, which is cester_assert_true underneath, so the log
 * prints the expression and never the value: the suite can say those envelopes
 * are wrong and cannot say what they are.
 *
 * This dumps them. It replicates spu_adsr_capture exactly - same drain with the
 * release override, same bit-11 sampling cadence - and traces 32 ENVX values
 * for four envelopes:
 *
 *   shift 14 up / down   CONTROLS. These PASS in the suite, so they must
 *                        reproduce their expected values here. If they do not,
 *                        this probe is not the harness and the shift-16 rows
 *                        below prove nothing about the suite.
 *   shift 16 up / down   the two that fail.
 *
 * Expected values are printed beside the observed ones at the indices the suite
 * actually asserts, so a divergence is readable without cross-referencing the
 * test source. Everything is bounded.
 */

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/pcsxhw.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

#include <stdint.h>

#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)
#define SPU_UPLOAD_ADDR 0x1080u

#define ATTACK(step, shift, exp) ((((step) & 3) << 8) | (((shift) & 31) << 10) | (!!(exp) << 15))
#define DECAY(shift) (((shift) & 15) << 4)
#define SUSTAIN(step, shift, level, direction, exp)                                  \
    ((((step) & 3) << 22) | (((shift) & 31) << 24) | (((level) & 15) << 0) |         \
     (!!(direction) << 30) | (!!(exp) << 31))
#define RELEASE(shift, exp) ((((shift) & 31) << 16) | (!!(exp) << 21))

#define DRAIN_MAX_TICKS 16
#define ONSET_MAX_SPINS 2000000
#define NSAMP 32

static const uint8_t kAdpcmSine[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x03, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
};

static uint8_t s_upload[128] __attribute__((aligned(4)));
static uint16_t s_envx[NSAMP];

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

static void flip(void) {
    int n = 0;
    while (!(SPU_STATUS & 0x0800)) { if (++n > 2000000) return; }
    while ((SPU_STATUS & 0x0800)) { if (++n > 2000000) return; }
}

static void reset_quiet(void) {
    DPCR |= 0x000b0000;
    SPU_CTRL = 0;
    SPU_VOL_MAIN_LEFT = 0; SPU_VOL_MAIN_RIGHT = 0;
    SPU_REVERB_LEFT = 0; SPU_REVERB_RIGHT = 0;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    SPU_PITCH_MOD_LOW = 0; SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0; SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0; SPU_REVERB_EN_HIGH = 0;
    SPU_REVERB_ADDR = 0xffff;
    SPU_RAM_DTC = 4;
    SPU_CTRL = 0x8000;
}

/* spu_adsr_capture, replicated including the bounded drain and onset. */
__attribute__((noinline))
static void busy(unsigned cycles) {
    unsigned n = cycles / 3;
    if (n == 0) return;
    __asm__ volatile("1: addiu %0, %0, -1 \n bnez %0, 1b \n nop \n" : "+r"(n) : : "memory");
}

/* delayCycles is inserted between the bit-11 edge and the key-on write. Key-on
   is otherwise pinned to that edge, and every later sample is pinned to a
   subsequent edge, so this delay is the ONLY thing that can move the whole
   trace - which makes it the direct measure of how many CPU cycles of drift
   equal one LSB at a given ramp slope. */
static void capture(uint32_t adsr, unsigned delayCycles) {
    reset_quiet();
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0; SPU_VOL_MAIN_RIGHT = 0;
    SPU_VOICES[1].adsrHi = (uint16_t)(RELEASE(0, 0) >> 16);
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    flip();
    unsigned drain = 0;
    while ((SPU_VOICES[1].currentVolume & 0xffff) != 0) {
        if (++drain > DRAIN_MAX_TICKS) break;
        flip();
    }

    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].volumeLeft = 0;
    SPU_VOICES[1].volumeRight = 0;
    flip();
    busy(delayCycles);
    SPU_VOICES[1].adsrLo = (uint16_t)(adsr & 0xffff);
    SPU_VOICES[1].adsrHi = (uint16_t)(adsr >> 16);
    SPU_KEY_OFF_LOW = 0; SPU_KEY_OFF_HIGH = 0;
    SPU_KEY_ON_LOW = 1u << 1;

    unsigned onset = 0;
    while ((SPU_VOICES[1].currentVolume & 0xffff) == 0) {
        if (++onset > ONSET_MAX_SPINS) break;
    }

    s_envx[0] = SPU_VOICES[1].currentVolume & 0xffff;
    for (int i = 1; i < NSAMP; i++) {
        flip();
        s_envx[i] = SPU_VOICES[1].currentVolume & 0xffff;
    }
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
}

static void dump(const char *tag, uint32_t adsr, unsigned d) {
    capture(adsr, d);
    ramsyscall_printf("OBS adsrsus %s adsr=%08x", tag, adsr);
    for (int i = 0; i < NSAMP; i++) ramsyscall_printf(" %04x", s_envx[i]);
    ramsyscall_printf("\n");
}

/* Print observed against expected at the indices the suite asserts, so a
   divergence reads without opening the test source. */
static void cmp(const char *tag, const int *idx, const uint16_t *exp, int n, int tol) {
    ramsyscall_printf("OBS adsrsus %s cmp", tag);
    int bad = 0;
    for (int k = 0; k < n; k++) {
        uint16_t got = s_envx[idx[k]];
        int ok = (got >= (uint16_t)(exp[k] - tol)) && (got <= (uint16_t)(exp[k] + tol));
        if (!ok) bad++;
        ramsyscall_printf(" [%d]exp=%04x got=%04x%s", idx[k], exp[k], got, ok ? "" : " BAD");
    }
    ramsyscall_printf("  bad=%d/%d\n", bad, n);
}

int main() {
    ramsyscall_printf("OBS adsrsus start\n");
    reset_quiet();
    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_dma_write(SPU_UPLOAD_ADDR, s_upload, 128);

    const uint32_t base = ATTACK(0, 1, 0) | DECAY(0) | RELEASE(0, 1);

    /* CONTROL: shift 14 up. Passes in the suite; must reproduce here. */
    {
        static const int idx[] = { 0, 1, 2, 4, 8, 12, 16, 20, 24, 28, 31 };
        static const uint16_t exp[] = { 0x1c00, 0x41b8, 0x4378, 0x46f8, 0x4df8, 0x54f8,
                                        0x5bf8, 0x62f8, 0x69f8, 0x70f8, 0x7638 };
        dump("ctrl_up_sh14  ", base | SUSTAIN(0, 14, 15, 0, 0), 0);
        cmp("ctrl_up_sh14  ", idx, exp, 11, 2);
    }

    /* CONTROL: shift 14 down. */
    {
        static const int idx[] = { 0, 1, 2, 4, 8, 12, 16, 20, 24, 28, 31 };
        static const uint16_t exp[] = { 0x1c00, 0x3e05, 0x3c05, 0x3805, 0x3005, 0x2805,
                                        0x2005, 0x1805, 0x1005, 0x0805, 0x0205 };
        dump("ctrl_down_sh14", base | SUSTAIN(0, 14, 15, 1, 0), 0);
        cmp("ctrl_down_sh14", idx, exp, 11, 2);
    }

    /* FAILING: shift 16 up. */
    {
        static const int idx[] = { 0, 1, 5, 10, 15, 20, 25, 31 };
        static const uint16_t exp[] = { 0x1c00, 0x4068, 0x4228, 0x4458, 0x4688, 0x48b8,
                                        0x4ae8, 0x4d88 };
        dump("fail_up_sh16  ", base | SUSTAIN(0, 16, 15, 0, 0), 0);
        cmp("fail_up_sh16  ", idx, exp, 8, 2);
    }

    /* FAILING: shift 16 down. */
    {
        static const int idx[] = { 0, 1, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30 };
        static const uint16_t exp[] = { 0x1c00, 0x3f85, 0x3e85, 0x3d05, 0x3b85, 0x3a05,
                                        0x3885, 0x3705, 0x3585, 0x3405, 0x3285, 0x3105 };
        dump("fail_down_sh16", base | SUSTAIN(0, 16, 15, 1, 0), 0);
        cmp("fail_down_sh16", idx, exp, 12, 2);
    }

    /* Repeat one failing case to separate a wrong expectation from jitter. */
    {
        static const int idx[] = { 0, 1, 5, 10, 15, 20, 25, 31 };
        static const uint16_t exp[] = { 0x1c00, 0x4068, 0x4228, 0x4458, 0x4688, 0x48b8,
                                        0x4ae8, 0x4d88 };
        dump("repeat_up_sh16", base | SUSTAIN(0, 16, 15, 0, 0), 0);
        cmp("repeat_up_sh16", idx, exp, 8, 2);
    }

    /* THE SWEEP. Shift-14 up has the steepest ramp (~448/tick) and is therefore
       the most sensitive to drift, so it is the best ruler. Expected envx[1] is
       0x41b8; the probe reads 0x41b1 at zero delay, 7 low. Find the delay that
       accounts for 7. */
    {
        static const unsigned kD[8] = { 0, 100, 200, 400, 800, 1600, 3200, 6400 };
        for (int i = 0; i < 8; i++) {
            capture(base | SUSTAIN(0, 14, 15, 0, 0), kD[i]);
            ramsyscall_printf("OBS adsrsus sweep d=%5u envx1=%04x envx2=%04x envx8=%04x envx31=%04x  d1=%d\n",
                              kD[i], s_envx[1], s_envx[2], s_envx[8], s_envx[31],
                              (int)s_envx[1] - 0x41b8);
        }
    }

    ramsyscall_printf("OBS adsrsus done\n");
    pcsx_exit(0);
    return 0;
}
