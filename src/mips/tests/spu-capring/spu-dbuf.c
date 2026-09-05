/*
 * Double-buffered capture via the SPU IRQ, against the current bit-11 method.
 *
 * Pixel's design. The voice-1 capture ring is 0x800..0xBFF, 512 samples, written
 * continuously. Put an IRQ at each half:
 *
 *   arm 0x800, wait   -> writer is at the ring start; KEY ON here
 *   arm 0xA00, wait   -> first half is complete and the writer is in the second
 *                        half, so READ 0x800..0x9FF now
 *   arm 0x800, wait   -> second half is complete and the writer is back in the
 *                        first, so READ 0xA00..0xBFF now
 *
 * Every read happens in the half the writer is not in, so it cannot tear, and
 * key-on is pinned to a hardware event rather than to a CPU poll - which is the
 * root of both the periodicity failures and the ADSR phase sensitivity.
 *
 * ACCEPTANCE CRITERION, and it is the whole point: the current method is
 * non-reproducible, so the new one has to be BYTE-IDENTICAL across repeats.
 * Both methods run three times each in one binary and print a hash of the full
 * 1024-byte ring. Three identical hashes from the IRQ method and three
 * differing ones from the bit-11 method is the result; three identical from
 * BOTH would mean this run cannot tell them apart and proves nothing.
 *
 * Bounded everywhere: every IRQ wait carries a poll cap and reports it.
 */

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/pcsxhw.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

#include <stdint.h>

#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)
#define SPU_UPLOAD_ADDR 0x1080u
#define CAP_LO 0x0800u
#define CAP_HI 0x0A00u
#define MAX_POLLS 4000000u

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

/* Same idiom as spu-irq.c, which is the established one in this tree. */
static void irq_arm(uint32_t byteAddr) {
    SPU_IRQ_ADDR = (uint16_t)(byteAddr >> 3);
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x8000 | 0x4000 | 0x0040;
    for (volatile int i = 0; i < 120; i++);
}
static uint32_t irq_wait(void) {
    for (uint32_t i = 0; i < MAX_POLLS; i++) {
        if (SPU_STATUS & 0x0040) return i + 1;
        __asm__ volatile("");
    }
    return 0;
}
static uint32_t irq_ack(void) {
    SPU_CTRL = SPU_CTRL & ~0x0040;
    for (uint32_t i = 0; i < 100000; i++) if ((SPU_STATUS & 0x0040) == 0) return 1;
    return 0;
}

static void flip(void) {
    int n = 0;
    while (!(SPU_STATUS & 0x0800)) { if (++n > 2000000) return; }
    while ((SPU_STATUS & 0x0800)) { if (++n > 2000000) return; }
}

static void keyon(void) {
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

/* A fixed quiet period gives every capture the SAME entry phase, and that is
   not what the suite has - there each capture inherits whatever phase the
   previous test left, which is why "the warmup is a property of where the
   capture lands in the test sequence" is already on file. A first run of this
   probe reproduced byte-identically under BOTH methods precisely because this
   was fixed, i.e. it controlled away the variable under study.
   The skew argument varies the entry phase deliberately. A method pinned to a
   hardware address event should be immune to it; one pinned to a CPU poll of a
   free-running flag should not. */
static void quiet(unsigned skew) {
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    for (volatile int i = 0; i < 200000; i++);
    for (volatile unsigned i = 0; i < skew; i++);
}

static uint32_t hash_ring(void) {
    uint32_t h = 5381;
    for (int i = 0; i < 512; i++) h = ((h << 5) + h) ^ (uint32_t)(uint16_t)s_cap[i];
    return h;
}

static void report(const char *tag, int rep, uint32_t extra1, uint32_t extra2) {
    int nz = 0, first = -1, last = -1;
    int16_t lo = 32767, hi = -32768;
    for (int i = 0; i < 512; i++) {
        int16_t v = s_cap[i];
        if (v) { nz++; if (first < 0) first = i; last = i; }
        if (v < lo) lo = v;
        if (v > hi) hi = v;
    }
    ramsyscall_printf("OBS dbuf %s rep=%d hash=%08lx nz=%3d first=%3d last=%3d lo=%6d hi=%6d p1=%lu p2=%lu\n",
                      tag, rep, hash_ring(), nz, first, last, lo, hi, extra1, extra2);
}

/* The proposed method. */
static void capture_irq(int rep, unsigned skew) {
    quiet(skew);
    irq_arm(CAP_LO);
    uint32_t p0 = irq_wait();
    irq_ack();
    keyon();

    irq_arm(CAP_HI);
    uint32_t p1 = irq_wait();
    irq_ack();
    spu_dma(CAP_LO, (uint32_t)&s_cap[0], 512, 1);

    irq_arm(CAP_LO);
    uint32_t p2 = irq_wait();
    irq_ack();
    spu_dma(CAP_HI, (uint32_t)&s_cap[256], 512, 1);

    if (!p0 || !p1 || !p2)
        ramsyscall_printf("OBS dbuf WARN irq never fired p0=%lu p1=%lu p2=%lu\n", p0, p1, p2);
    report("irq   ", rep, p1, p2);
    quiet(0);
}

/* The current method, for contrast: poll bit 11, key on, poll again, read. */
static void capture_bit11(int rep, unsigned skew) {
    quiet(skew);
    SPU_CTRL = (SPU_CTRL & ~0x0040);
    flip();
    keyon();
    flip();
    spu_dma(CAP_LO, (uint32_t)&s_cap[0], 1024, 1);
    report("bit11 ", rep, 0, 0);
    quiet(0);
}

int main() {
    ramsyscall_printf("OBS dbuf start\n");

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

    /* Same skew ladder for both methods so the comparison is like-for-like. */
    static const unsigned kSkew[6] = { 0, 9000, 18000, 27000, 36000, 45000 };
    for (int r = 0; r < 6; r++) capture_bit11(r, kSkew[r]);
    for (int r = 0; r < 6; r++) capture_irq(r, kSkew[r]);

    ramsyscall_printf("OBS dbuf done\n");
    pcsx_exit(0);
    return 0;
}
