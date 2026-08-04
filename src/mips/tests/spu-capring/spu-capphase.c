/*
 * Where is the capture ring's write pointer when SPUSTAT bit 11 flips?
 *
 * Measured: one half-lap after key-on, silicon has written 505 of 512 ring
 * samples and Redux ~250, off the same bit-11 edge. Whatever bit 11 marks, the
 * two platforms do not agree about where a lap begins - which matters because
 * the obvious harness fix ("read a full lap after key-on") assumes they do.
 *
 * The write pointer is not readable, so infer it. Drain the ring to all-zero
 * with the voice off, wait for a bit-11 edge, key on, wait a SHORT calibrated
 * delay, and read. The first nonzero index is where writing began - i.e. the
 * ring position at the edge. That is the phase, directly.
 *
 * Sweeping the delay turns one point into a trajectory: first should stay put
 * while last advances, and the rate at which last advances is the ring's write
 * rate in samples per CPU cycle. If first MOVES across the sweep, the edge is
 * not at a fixed ring position and that is itself the answer.
 *
 * One lap is 512 samples at 44100Hz = 11.61ms = ~393k cycles at 33.87MHz, so
 * the eighth-lap steps below are ~49k cycles each. Those constants are nominal;
 * the measurement does not depend on them being right, only on them being the
 * same on both platforms.
 *
 * Controls: the drained read must be all-zero before every point (printed, not
 * assumed), and the widest delay must show more written than the narrowest -
 * if the sweep does not move, the delay is not doing anything and no phase
 * number here is real.
 */

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/pcsxhw.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

#include <stdint.h>

#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)
#define SPU_UPLOAD_ADDR 0x1080u
#define CAPTURE_VOICE1 0x0800u
#define EIGHTH_LAP 49000u

static const uint8_t kAdpcmSine[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x03, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
};

static uint8_t s_upload[128] __attribute__((aligned(4)));
static int16_t s_cap[512] __attribute__((aligned(4)));

static void spu_dma(uint32_t spuByteAddr, uint32_t cpuAddr, uint32_t bytes, int isRead) {
    const uint16_t tsa = (uint16_t)(spuByteAddr >> 3);
    const uint16_t modeBits = isRead ? 0x0030 : 0x0020;
    const uint32_t delay = isRead ? 0x22000000 : 0x20000000;
    const uint32_t chcr = isRead ? 0x01000200 : 0x01000201;
    SPU_RAM_DTA = tsa;
    for (int i = 0; i < 0xF01 && (SPU_RAM_DTA & 0xffff) != tsa; i++);
    SPU_CTRL = (SPU_CTRL & ~0x0030) | modeBits;
    for (volatile int i = 0; i < 60; i++);
    for (int i = 0; i < 0xF01 && (SPU_STATUS & 0x30) != modeBits; i++);
    SPU_DELAY = (SPU_DELAY & 0xf0ffffff) | delay;
    uint32_t blocks = (bytes >> 6) + ((bytes & 0x3f) ? 1 : 0);
    DMA_CTRL[DMA_SPU].MADR = cpuAddr & 0x1fffffff;
    DMA_CTRL[DMA_SPU].BCR = (blocks << 16) | 0x10;
    DMA_CTRL[DMA_SPU].CHCR = chcr;
    for (int i = 0; i < 0x100000 && (DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0; i++);
    SPU_CTRL = (SPU_CTRL & ~0x0030);
    for (volatile int i = 0; i < 60; i++);
}

static int half_lap(void) {
    int n = 0;
    while (!(SPU_STATUS & 0x0800)) { if (++n > 2000000) return 0; }
    while ((SPU_STATUS & 0x0800)) { if (++n > 2000000) return 0; }
    return 1;
}

__attribute__((noinline))
static void busy_wait(unsigned cycles) {
    unsigned n = cycles / 3;
    if (n == 0) return;
    __asm__ volatile("1: addiu %0, %0, -1 \n bnez %0, 1b \n nop \n" : "+r"(n) : : "memory");
}

static void init_spu(void) {
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

/* One sweep point. Returns nothing; prints everything, including the drained
   control, because a phase number taken over a dirty ring is meaningless. */
static void point(unsigned delayCycles, int eighths) {
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    busy_wait(1200000);   /* > 2 laps keyed off, ring goes to zero */

    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    int dirty = 0;
    for (int i = 0; i < 512; i++) if (s_cap[i]) dirty++;

    half_lap();
    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].adsrLo = 0x000f;
    SPU_VOICES[1].adsrHi = 0x1fc0;
    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;
    SPU_KEY_OFF_LOW = 0; SPU_KEY_OFF_HIGH = 0;
    SPU_KEY_ON_LOW = 1u << 1;

    busy_wait(delayCycles);
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);

    int nz = 0, first = -1, last = -1, runs = 0, prev = 0;
    for (int i = 0; i < 512; i++) {
        int v = s_cap[i] != 0;
        if (v) { nz++; if (first < 0) first = i; last = i; }
        if (v && !prev) runs++;
        prev = v;
    }
    ramsyscall_printf("OBS capphase eighths=%d delay=%6u dirtyBeforeKeyon=%3d nz=%3d first=%3d last=%3d runs=%d\n",
                      eighths, delayCycles, dirty, nz, first, last, runs);
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
}

int main() {
    ramsyscall_printf("OBS capphase start eighthlap=%u\n", EIGHTH_LAP);
    init_spu();
    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_dma(SPU_UPLOAD_ADDR, (uint32_t)s_upload, 128, 0);
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;

    for (int e = 1; e <= 6; e++) point(EIGHTH_LAP * (unsigned)e, e);

    /* Repeat the narrowest point to show whether the phase is stable run to
       run, or wanders. Same delay as eighths=1 above. */
    point(EIGHTH_LAP, 1);

    ramsyscall_printf("OBS capphase done\n");
    pcsx_exit(0);
    return 0;
}
