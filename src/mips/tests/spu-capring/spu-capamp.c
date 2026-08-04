/*
 * Where in the capture ring does the 27957 peak live, and why is it gone a lap
 * later?
 *
 * Measured on silicon: a read taken a HALF lap after key-on peaks at 27957 -
 * exactly sine.test.pcm's max - while every read taken a FULL lap after key-on
 * peaks at 14278, and Redux reads 14278 in every variant and never produces
 * 27957 at all. 27957 is ~0.975 of the sample's theoretical max (nibble 7 at
 * shift 0 filter 0 is 7<<12 = 28672); 14278 is ~0.498 of it. A factor of two
 * apart, which is suggestive and is exactly why it needs measuring rather than
 * a story.
 *
 * This reports the ring in eight 64-sample blocks so the peak can be located
 * rather than summarised, at four points in time. It also does the one thing
 * the variant matrix never did: READ THE RING AFTER THE DRAIN AND BEFORE
 * KEY-ON. Variant A showed nz=505 only a half lap after key-on, which is far
 * more nonzero samples than a half lap of new data can account for - so either
 * the drain does not clear the ring, or the ring holds something the drain
 * cannot reach. Unmeasured either way; this measures it.
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
static int s_run;

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

/* Eight blocks of 64. A summary hides where a peak is; this does not. */
static void octants(const char *tag) {
    ramsyscall_printf("OBS capamp r%d %s", s_run, tag);
    for (int b = 0; b < 8; b++) {
        int16_t lo = 32767, hi = -32768;
        int nz = 0;
        for (int i = b * 64; i < b * 64 + 64; i++) {
            int16_t v = s_cap[i];
            if (v) nz++;
            if (v < lo) lo = v;
            if (v > hi) hi = v;
        }
        ramsyscall_printf(" [%d:%d/%d..%d]", b, nz, lo, hi);
    }
    ramsyscall_printf("\n");
}

int main() {
    s_run++;
    ramsyscall_printf("OBS capamp RUN %d start\n", s_run);

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

    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_dma(SPU_UPLOAD_ADDR, (uint32_t)s_upload, 128, 0);

    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    busy_wait(800000);

    /* The check variant A never made: is the ring actually clear before key-on?
       A read 505 nonzero only a half lap in, which a half lap cannot supply. */
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    octants("afterdrain ");

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

    half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    octants("halflap    ");

    half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    octants("fulllap    ");

    half_lap(); half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    octants("twolaps    ");

    half_lap(); half_lap(); half_lap(); half_lap();
    spu_dma(CAPTURE_VOICE1, (uint32_t)s_cap, 1024, 1);
    octants("fourlaps   ");

    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    ramsyscall_printf("OBS capamp RUN %d done\n", s_run);
    pcsx_exit(0);
    return 0;
}
