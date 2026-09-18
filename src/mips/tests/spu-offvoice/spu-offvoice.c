/*
 * SPU interrupt latch semantics, and whether a silent voice keeps reading.
 *
 * Two properties psx-spx documents, both observable from the guest through
 * SPUCNT.6 and SPUSTAT.6 alone, so this needs no capture buffer and no golden.
 *
 * Phase 1, with the voice audibly playing: the SPU disables its own interrupt
 * when it fires. SPUCNT bit 6 is documented "IRQ9 Enable (0=Disabled/
 * Acknowledge, 1=Enabled)" and SPUSTAT bit 6 is the IRQ9 flag, so after an
 * address match the flag must read set, the enable must read clear, and writing
 * the enable back to 0 must acknowledge. Without the self-disable the same
 * address keeps re-firing for as long as the voice loops over it, which is what
 * a streaming driver re-pointing IRQA per chunk sees as extra interrupts.
 *
 * Phase 2, with the same voice keyed off and its envelope down to zero: the
 * ADPCM readout does not stop. "All voices are permanently reading data from
 * SPU RAM - even in Noise mode, even if the Voice Volume is zero, and even if
 * the ADSR pattern has finished the Release period - so even inaudible voices
 * can trigger IRQs" (psx-spx, Voice Interrupt). ENVX is sampled first and has to
 * read zero, which is what makes phase 2 a statement about a silent voice rather
 * than about one that merely got quieter.
 *
 * The sample is an eight-block loop whose last block carries the loop-end and
 * repeat flags, so the voice never runs off its own end and the only thing that
 * silences it is the key-off. IRQA sits on a block boundary in the middle of it,
 * because psx-spx warns a mid-block address does not trigger reliably.
 *
 * DMA channel 4 is enabled in DPCR before the upload. Without it the transfer is
 * a silent no-op: the voice then reads zeroed SPU RAM, every flag byte it decodes
 * is 00, and it walks forward through memory forever - which from the guest side
 * is indistinguishable from a voice running normally.
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
#define SPU_IRQ_BYTE_ADDR (SPU_UPLOAD_ADDR + 4 * 16)

#define SPU_CTRL_ENABLE 0x8000u
#define SPU_CTRL_UNMUTE 0x4000u
#define SPU_CTRL_IRQ_ENABLE 0x0040u
#define SPU_STATUS_IRQ_FLAG 0x0040u

/* Both polls are generous on purpose: the SPU runs on its own thread under the
   emulator and on its own clock on silicon, so any tight constant is a race. One
   lap of the eight-block sample is a few milliseconds at this pitch, so a live
   readout matches early and only a dead one spends the whole budget. */
#define IRQ_POLL_LIMIT 4000000u
#define ENVX_POLL_LIMIT 4000000u

static uint8_t s_sample[128] __attribute__((aligned(4)));

static void make_sample(void) {
    for (int block = 0; block < 8; block++) {
        uint8_t *p = &s_sample[block * 16];
        p[0] = 0x00;
        p[1] = 0x00;
        if (block == 0) p[1] = 0x06;  /* loop start */
        if (block == 7) p[1] = 0x03;  /* loop end + repeat: this never stops */
        uint8_t nybble = (uint8_t)((block + 1) & 7);
        uint8_t packed = (uint8_t)(nybble | (nybble << 4));
        for (int i = 2; i < 16; i++) p[i] = packed;
    }
}

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

/* Arm IRQA and enable IRQ9, leaving the transfer-mode bits alone. */
static void irq_arm(uint32_t byteAddr) {
    SPU_IRQ_ADDR = (uint16_t)(byteAddr >> 3);
    SPU_CTRL = (SPU_CTRL & ~0x0030) | SPU_CTRL_ENABLE | SPU_CTRL_UNMUTE | SPU_CTRL_IRQ_ENABLE;
    for (volatile int i = 0; i < 120; i++);
}

/* Acknowledge by writing the enable bit to 0, and report whether the status flag
   actually went away. Returns 0 if it stayed set. */
static uint32_t irq_ack(void) {
    SPU_CTRL = SPU_CTRL & ~SPU_CTRL_IRQ_ENABLE;
    for (uint32_t i = 0; i < 100000; i++) {
        if ((SPU_STATUS & SPU_STATUS_IRQ_FLAG) == 0) return 1;
    }
    return 0;
}

static uint32_t irq_poll(uint32_t limit) {
    for (uint32_t i = 0; i < limit; i++) {
        if (SPU_STATUS & SPU_STATUS_IRQ_FLAG) return i + 1;
        __asm__ volatile("");
    }
    return 0;
}

int main() {
    ramsyscall_printf("SPUOFFVOICE: start\n");

    DPCR |= 0x000b0000;  /* DMA4 (SPU) on, or the upload below is a silent no-op */
    SPU_CTRL = 0;
    for (volatile int i = 0; i < 60; i++);
    SPU_RAM_DTC = 4;  /* required on real hardware for SPU RAM transfers */
    for (volatile int i = 0; i < 60; i++);
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_IRQ_ADDR = 0;
    for (volatile int i = 0; i < 60; i++);

    make_sample();
    spu_dma_write(SPU_UPLOAD_ADDR, s_sample, sizeof(s_sample));

    /* Release shift 0 with a linear release, so the key-off in phase 2 takes the
       envelope to zero promptly. Sustain holds at full, so phase 1 measures a
       voice that is genuinely playing. */
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].adsrLo = 0x000f;
    SPU_VOICES[1].adsrHi = 0x0000;
    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;

    SPU_CTRL = SPU_CTRL_ENABLE | SPU_CTRL_UNMUTE;
    for (volatile int i = 0; i < 60; i++);

    /* ---------------- Phase 1: the interrupt disables itself ---------------- */
    irq_arm(SPU_IRQ_BYTE_ADDR);
    SPU_KEY_ON_LOW = 1u << 1;
    SPU_KEY_ON_HIGH = 0;

    const uint32_t pollsOn = irq_poll(IRQ_POLL_LIMIT);
    const int firedOn = pollsOn != 0;
    const uint16_t statusAtFire = SPU_STATUS & 0xffff;
    const uint16_t ctrlAtFire = SPU_CTRL & 0xffff;
    const uint16_t envxAtFire = SPU_VOICES[1].currentVolume & 0xffff;
    const uint32_t ackCleared = irq_ack();
    const uint16_t statusAfterAck = SPU_STATUS & 0xffff;

    ramsyscall_printf("SPUOFFVOICE: on-voice fired=%d polls=%lu stat=%04x ctrl=%04x envx=%04x "
                      "ack=%lu statAck=%04x\n",
                      firedOn, pollsOn, statusAtFire, ctrlAtFire, envxAtFire, ackCleared,
                      statusAfterAck);

    /* ---------------- Phase 2: the silent voice keeps reading ---------------- */
    SPU_KEY_OFF_LOW = 1u << 1;
    SPU_KEY_OFF_HIGH = 0;

    uint32_t envxPolls = 0;
    while (envxPolls < ENVX_POLL_LIMIT && (SPU_VOICES[1].currentVolume & 0xffff) != 0) {
        envxPolls++;
        __asm__ volatile("");
    }
    /* Let the release settle past the batch it landed in, so the voice is fully
       idle rather than merely at zero volume for one batch. */
    for (volatile int i = 0; i < 200000; i++);
    const uint16_t envxAfterOff = SPU_VOICES[1].currentVolume & 0xffff;
    const uint16_t endxWhilePlaying = SPU_ENDX_LOW & 0xffff;

    irq_arm(SPU_IRQ_BYTE_ADDR);
    const uint32_t pollsOff = irq_poll(IRQ_POLL_LIMIT);
    const int firedOff = pollsOff != 0;
    const uint16_t statusOff = SPU_STATUS & 0xffff;
    const uint16_t envxAtFireOff = SPU_VOICES[1].currentVolume & 0xffff;
    (void)irq_ack();

    ramsyscall_printf("SPUOFFVOICE: off-voice fired=%d polls=%lu stat=%04x envxIdle=%04x "
                      "envxAtFire=%04x endx=%04x envxPolls=%lu\n",
                      firedOff, pollsOff, statusOff, envxAfterOff, envxAtFireOff,
                      endxWhilePlaying, envxPolls);

    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_CTRL = 0;

    /* ---------------------------- Verdict ---------------------------- */
    /* Each check says what its failure means, because an index in a log is not a
       diagnosis. The first two are controls for the third: ENDX proves the voice
       actually reached its end block, so the upload landed and the cursor moved,
       and a flag that sets for a PLAYING voice proves the instrument is live.
       Without both, phase 2's silence would say nothing about a silent voice. */
    int failures = 0;

    if (!(endxWhilePlaying & 2)) {
        ramsyscall_printf("SPUOFFVOICE: FAIL - ENDX never latched for voice 1 while it played; the "
                          "sample never reached its end block, so the upload or the decode cursor "
                          "is broken and nothing below is meaningful\n");
        failures++;
    }

    if (!firedOn) {
        ramsyscall_printf("SPUOFFVOICE: FAIL - SPUSTAT.6 never set for a PLAYING voice crossing "
                          "IRQA; the IRQ flag is not implemented, and phase 2 proves nothing\n");
        failures++;
    } else {
        if (ctrlAtFire & SPU_CTRL_IRQ_ENABLE) {
            ramsyscall_printf("SPUOFFVOICE: FAIL - SPUCNT.6 still set after the match; the SPU did "
                              "not disable its own interrupt, so the address keeps re-firing\n");
            failures++;
        }
        if (!ackCleared) {
            ramsyscall_printf("SPUOFFVOICE: FAIL - writing SPUCNT.6=0 did not acknowledge; "
                              "SPUSTAT.6 stayed set at %04x\n", statusAfterAck);
            failures++;
        }
    }

    if (envxAfterOff != 0) {
        ramsyscall_printf("SPUOFFVOICE: FAIL - the voice never went silent after key-off "
                          "(ENVX=%04x); phase 2 is not testing a silent voice\n", envxAfterOff);
        failures++;
    } else if (!firedOff) {
        ramsyscall_printf("SPUOFFVOICE: FAIL - a keyed-off voice stopped reading SPU RAM; no IRQA "
                          "match in %lu polls, while the same voice playing matched in %lu\n",
                          (unsigned long)IRQ_POLL_LIMIT, pollsOn);
        failures++;
    }

    ramsyscall_printf("SPUOFFVOICE: %s (endx=%04x firedOn=%d ctrl=%04x ack=%lu envxIdle=%04x "
                      "firedOff=%d)\n", failures ? "FAILURE" : "PASS", endxWhilePlaying, firedOn,
                      ctrlAtFire, ackCleared, envxAfterOff, firedOff);
    pcsx_exit(failures ? 1 : 0);
    return failures ? 1 : 0;
}
