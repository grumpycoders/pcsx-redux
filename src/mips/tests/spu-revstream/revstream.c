/*
 * Free-running reverb stimulus for the I2S digital-audio tap.
 *
 * The work-area capture in tests/spu/spu-reverb.c reads SPU RAM after a fixed
 * number of sync windows, which makes the result a snapshot whose contents move
 * with the key-on phase. This one is the opposite shape: program the room
 * preset, key one voice on exactly once, unmute the final mix, and then never
 * touch the SPU again. Everything after that point is the SPU running free, so
 * the only quantity that varies between runs is where the analyzer's window
 * lands - which cross-correlation can recover.
 *
 * The single key-on is the whole point. A sequencer that retriggers notes from
 * CPU code reintroduces run-to-run timing drift at every note boundary, and
 * that drift is indistinguishable from a reverb difference once it is in the
 * stream.
 */

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

#include <stdint.h>

#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)

#define SPU_UPLOAD_ADDR 0x1080u
#define SPU_REVERB_ROOM_SIZE 0x26c0u
#define SPU_REVERB_ROOM_BASE (0x80000u - SPU_REVERB_ROOM_SIZE)
#define SPU_REVERB_ROOM_BASE_REG (SPU_REVERB_ROOM_BASE >> 3)

/* Sustained sine, loop flags set so the voice never runs off the end. Same
   bytes as tests/spu/spu.c kAdpcmSine - keep them identical so a capture here
   is comparable with the dry per-voice goldens. */
static const uint8_t kAdpcmSine[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x03, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
};

static const uint16_t kReverbRoomPreset[32] = {
    0x007d, 0x005b, 0x6d80, 0x54b8, 0xbed0, 0x0000, 0x0000, 0xba80,
    0x5800, 0x5300, 0x04d6, 0x0333, 0x03f0, 0x0227, 0x0374, 0x01ef,
    0x0334, 0x01b5, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x01b4, 0x0136, 0x00b8, 0x005c, 0x8000, 0x8000,
};

static uint8_t s_upload[128] __attribute__((aligned(4)));
static uint8_t s_zeros[0x800] __attribute__((aligned(4)));

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
    while ((DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0) __asm__ volatile("");

    SPU_CTRL = (SPU_CTRL & ~0x0030);
    for (volatile int i = 0; i < 60; i++);
}

static void spu_reset_quiet(void) {
    DPCR |= 0x000b0000;
    SPU_CTRL = 0;
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_REVERB_LEFT = 0;
    SPU_REVERB_RIGHT = 0;
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_PITCH_MOD_LOW = 0;
    SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0;
    SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0;
    SPU_REVERB_EN_HIGH = 0;
    SPU_REVERB_ADDR = 0xffff;
    SPU_RAM_DTC = 4;
    SPU_CTRL = 0x8000;
}

int main(void) {
    ramsyscall_printf("REVSTREAM: start\n");

    spu_reset_quiet();

    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_dma_write(SPU_UPLOAD_ADDR, s_upload, 128);

    /* Reverb writes stay disabled while the work area is cleared, otherwise the
       SPU races the DMA and the first seconds of tail are whatever was in RAM. */
    SPU_CTRL = 0x8000 | 0x4000;
    for (unsigned i = 0; i < sizeof(s_zeros); i++) s_zeros[i] = 0;
    for (unsigned off = 0; off < SPU_REVERB_ROOM_SIZE; off += sizeof(s_zeros)) {
        unsigned chunk = SPU_REVERB_ROOM_SIZE - off;
        if (chunk > sizeof(s_zeros)) chunk = sizeof(s_zeros);
        spu_dma_write(SPU_REVERB_ROOM_BASE + off, s_zeros, chunk);
    }

    SPU_REVERB_ADDR = SPU_REVERB_ROOM_BASE_REG;
    {
        volatile uint16_t *regs = (volatile uint16_t *)SPU_REVERB;
        for (unsigned i = 0; i < 32; i++) regs[i] = kReverbRoomPreset[i];
    }

    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;
#ifdef REVSTREAM_DRY
    /* Negative control: identical in every respect except that the voice never
       reaches the reverb unit. If a capture of this is indistinguishable from
       the reverb build, the reverb build was never observing reverb. */
    SPU_REVERB_EN_LOW = 0;
#else
    SPU_REVERB_EN_LOW = 1u << 1;
#endif
    SPU_REVERB_EN_HIGH = 0;

    /* Unlike the work-area test, the final mix is what is being observed here,
       so main and reverb output volumes come up. */
    SPU_VOL_MAIN_LEFT = 0x3fff;
    SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_REVERB_LEFT = 0x3fff;
    SPU_REVERB_RIGHT = 0x3fff;

#ifdef REVSTREAM_DRY
    SPU_CTRL = 0x8000 | 0x4000;
#else
    SPU_CTRL = 0x8000 | 0x4000 | 0x0080;
#endif

    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].adsrLo = 0x000f;
    SPU_VOICES[1].adsrHi = 0x1fc0;
    SPU_KEY_OFF_LOW = 0;
    SPU_KEY_OFF_HIGH = 0;

    /* Align to the same capture-half edge the dry tests use, then the one and
       only key-on. Nothing below this line touches the SPU. */
    while (!(SPU_STATUS & 0x0800));
    while ((SPU_STATUS & 0x0800));
    SPU_KEY_ON_LOW = 1u << 1;

#ifdef REVSTREAM_DRY
    ramsyscall_printf("REVSTREAM(DRY): keyon, free-running\n");
#else
    ramsyscall_printf("REVSTREAM: keyon, free-running\n");
#endif

    while (1) __asm__ volatile("");
    return 0;
}
