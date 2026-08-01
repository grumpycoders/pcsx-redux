/*
 * SPUSTAT ENDX (1F801D9C/1D9E) hardware check.
 *
 * ENDX carries one bit per voice, set when the voice consumes an ADPCM block
 * carrying the end flag and cleared on key-on. Games poll it to notice that a
 * one-shot sample has finished.
 *
 * Two phases. Phase 1 keys voices 0 and 1 on with a looping sample and lets
 * them run past the end block, so both bits latch. Phase 2 keys voice 1 on
 * again from that known-set state and samples the register: voice 1 must go
 * clear and voice 0, never keyed on again, must stay set. Going through a set
 * state first is what makes the clear observable on both hardware (where the
 * bits are already latched from reset) and the emulator (where they start at
 * zero), and it makes voice 0 a control rather than a constant.
 */

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

#include <stdint.h>

#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)
#define SPU_ENDX_LOW (*(volatile uint16_t *)0x1f801d9c)
#define SPU_ENDX_HIGH (*(volatile uint16_t *)0x1f801d9e)
#define SPU_UPLOAD_ADDR 0x1080u

static const uint8_t kAdpcmSine[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x03, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
};

static uint8_t s_upload[128] __attribute__((aligned(4)));

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

int main() {
    ramsyscall_printf("SPUENDX: start\n");

    SPU_CTRL = 0;
    for (volatile int i = 0; i < 60; i++);
    SPU_RAM_DTC = 4;  // required on real hardware for SPU RAM transfers
    for (volatile int i = 0; i < 60; i++);
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    for (volatile int i = 0; i < 60; i++);

    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
#ifdef ENDX_ONESHOT
    /* end WITHOUT repeat: the voice stops here instead of looping. Silicon
       shows ENDX clear for a LOOPING voice, so the trigger may be stop-only. */
    s_upload[3 * 16 + 1] = 0x01;
#endif
    spu_dma_write(SPU_UPLOAD_ADDR, s_upload, 128);

    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].adsrLo = 0x000f;
    SPU_VOICES[1].adsrHi = 0x80ff;
    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;

    /* Voice 0 is the control: keyed on once in phase 1 so its bit latches, then
       never keyed on again. Phase 2 must leave it SET. */
    SPU_VOICES[0].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[0].sampleRate = 0x1000;
    SPU_VOICES[0].adsrLo = 0x000f;
    SPU_VOICES[0].adsrHi = 0x80ff;
    SPU_VOICES[0].volumeLeft = 0x3fff;
    SPU_VOICES[0].volumeRight = 0x3fff;

    ramsyscall_printf("SPUENDX: before keyon ENDX=%04x%04x\n", SPU_ENDX_HIGH & 0xffff,
                      SPU_ENDX_LOW & 0xffff);

    SPU_CTRL = 0x8000 | 0x4000;
    for (volatile int i = 0; i < 60; i++);
    SPU_KEY_ON_LOW = (1u << 1) | (1u << 0);
    SPU_KEY_ON_HIGH = 0;

    /* Phase 1: wait for the voice to run past its end block and LATCH. Poll
       rather than delaying a fixed amount: the emulator's SPU can run far
       behind the CPU, so any constant is either wrong there or wasteful on
       hardware. Latching is also the positive control - it proves the register
       reads high here, so a later low reading is a real clear and not a dead
       instrument. */
    int spins = 0;
    while (spins < 400 && (SPU_ENDX_LOW & 3) != 3) {
        for (volatile int i = 0; i < 900000; i++);
        spins++;
    }
    {
        uint16_t v = SPU_ENDX_LOW & 0xffff;
        ramsyscall_printf("SPUENDX: after-latch ENDX_LOW=%04x voice1=%s voice0=%s spins=%d\n", v,
                          (v & 2) ? "SET" : "clear", (v & 1) ? "SET" : "clear", spins);
        if ((v & 3) != 3) ramsyscall_printf("SPUENDX: NO LATCH - phase 2 proves nothing\n");
    }

    /* Phase 2: key the SAME voice on again from a known-SET state and sample the
       register. Starting from set is what makes this discriminating: on silicon
       the bits are latched from reset, but under Redux they start clear, so only
       a set-then-key-on sequence can test the clear on both sides.
       Voice 0 is never keyed on, so its bit must hold its value throughout -
       that separates "key-on cleared voice 1" from "something wiped ENDX". */
    SPU_KEY_ON_LOW = 1u << 1;
    SPU_KEY_ON_HIGH = 0;

    static uint16_t endxWindow[16];
    for (int i = 0; i < 16; i++) {
        endxWindow[i] = SPU_ENDX_LOW & 0xffff;
        for (volatile int j = 0; j < 20; j++);
    }
    for (int i = 0; i < 16; i++) {
        ramsyscall_printf("SPUENDX: keyon2+%02d ENDX_LOW=%04x voice1=%s voice0=%s\n", i,
                          endxWindow[i], (endxWindow[i] & 2) ? "SET" : "clear",
                          (endxWindow[i] & 1) ? "SET" : "clear");
    }

    /* Then let it run again: the voice reaches the end block and must re-latch. */
    for (int t = 0; t < 4; t++) {
        for (volatile int j = 0; j < 12; j++) for (volatile int i = 0; i < 900000; i++);
        ramsyscall_printf("SPUENDX: t=%d ENDX=%04x%04x voice1=%s envx=%04x stat=%04x\n", t,
                          SPU_ENDX_HIGH & 0xffff, SPU_ENDX_LOW & 0xffff,
                          (SPU_ENDX_LOW & 2) ? "SET" : "clear",
                          SPU_VOICES[1].currentVolume & 0xffff, SPU_STATUS & 0xffff);
    }
    ramsyscall_printf("SPUENDX: done\n");
    while (1) __asm__ volatile("");
    return 0;
}
