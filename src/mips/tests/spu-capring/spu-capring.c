/*
 * Why does this probe capture silence on silicon where run_voice1_with_sample
 * captures a sine from the same region?
 *
 * The first version of this probe read lo=-65 hi=0 out of the voice-1 capture
 * ring on hardware. That is not a hardware property: sine.test.pcm (min -16320,
 * max 27957) was captured from silicon through the suite's own path out of the
 * same 0x0800 region, so the console captures full amplitude there and this
 * probe does not. The fault is the instrument.
 *
 * The fault is silicon-only - under Redux the probe reads the intended waveform,
 * and its lo matches the golden's min exactly - so it cannot be bisected
 * locally. Four variants in one binary, one ticket, each toggling ONE thing
 * against the known-good path:
 *
 *   A  suite replica: spu_reset_quiet, busy-wait drain, key on, ONE bit-11
 *      flip, ONE read. This is run_voice1_with_sample verbatim and is the
 *      POSITIVE CONTROL - if A does not show full amplitude, the replica is
 *      wrong and B/C/D say nothing.
 *   B  A, but read a FULL lap after key-on instead of a half. Isolates the fill
 *      question on hardware, on a signal known good from A.
 *   C  A, but then read the ring EIGHT more times back to back, reporting the
 *      first and last. Isolates repeated DMA reads during playback - each read
 *      flips SPU_CTRL transfer mode twice, and the first version of this probe
 *      did 48 of them while the voice was running.
 *   D  the original probe's own init and lap-counted drain, single read.
 *      Isolates the setup path.
 *
 * A vs D says whether it is setup. A vs C says whether it is the repeated reads.
 * A vs B is the fill answer, re-taken on hardware.
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

/* Byte-for-byte what spu.c does, so the control is a control. */
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

/* The probe's own init, as originally written. */
static void init_mine(void) {
    SPU_CTRL = 0;
    for (volatile int i = 0; i < 60; i++);
    SPU_RAM_DTC = 4;
    for (volatile int i = 0; i < 60; i++);
    DPCR |= 0x000b0000;
    SPU_VOL_MAIN_LEFT = 0; SPU_VOL_MAIN_RIGHT = 0;
    SPU_REVERB_LEFT = 0; SPU_REVERB_RIGHT = 0;
    SPU_PITCH_MOD_LOW = 0; SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0; SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0; SPU_REVERB_EN_HIGH = 0;
    SPU_REVERB_ADDR = 0xffff;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
}

static void keyon_voice1(void) {
    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].adsrLo = 0x000f;
    SPU_VOICES[1].adsrHi = 0x1fc0;
    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;
    SPU_KEY_OFF_LOW = 0; SPU_KEY_OFF_HIGH = 0;
    SPU_KEY_ON_LOW = 1u << 1;
}

static void report(const char *tag) {
    int nz = 0, first = -1, last = -1;
    int16_t lo = 32767, hi = -32768;
    for (int i = 0; i < 512; i++) {
        int16_t v = s_cap[i];
        if (v) { nz++; if (first < 0) first = i; last = i; }
        if (v < lo) lo = v;
        if (v > hi) hi = v;
    }
    ramsyscall_printf("OBS capring %s nz=%3d first=%3d last=%3d lo=%6d hi=%6d\n",
                      tag, nz, first, last, lo, hi);
}

static void upload(void) {
    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_dma(SPU_UPLOAD_ADDR, (uint32_t)s_upload, 128, 0);
}

int main() {
    ramsyscall_printf("OBS capring variants start\n");

    /* A: run_voice1_with_sample verbatim. POSITIVE CONTROL. */
    reset_quiet();
    upload();
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    busy_wait(800000);
    half_lap();
    keyon_voice1();
    half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    report("A_suite_replica    ");
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;

    /* B: A, but a full lap after key-on. */
    reset_quiet();
    upload();
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    busy_wait(800000);
    half_lap();
    keyon_voice1();
    half_lap(); half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    report("B_full_lap         ");
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;

    /* C: A, then eight more reads back to back while the voice runs. */
    reset_quiet();
    upload();
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    busy_wait(800000);
    half_lap();
    keyon_voice1();
    half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    report("C_read1of9         ");
    for (int i = 0; i < 8; i++) spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    report("C_read9of9         ");
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;

    /* D: the original probe's init and lap-counted drain. */
    init_mine();
    upload();
    SPU_CTRL = 0x8000 | 0x4000;
    for (volatile int i = 0; i < 60; i++);
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    for (int i = 0; i < 8; i++) { half_lap(); half_lap(); }
    half_lap(); half_lap();
    keyon_voice1();
    half_lap(); half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    report("D_mine_init        ");
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;

    ramsyscall_printf("OBS capring variants done\n");
    pcsx_exit(0);
    return 0;
}
