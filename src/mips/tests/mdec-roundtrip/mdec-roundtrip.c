/*
 * MDEC roundtrip rig.
 *
 * Reads a job file over pcdrv, pushes it through the real MDEC, writes the
 * decoded output back over pcdrv. Runs identically under pcsx-redux and on a
 * devkit, which is the point: the same binary and the same job file give an
 * emulator arm and a hardware arm that differ in nothing but the silicon.
 *
 * Job file layout, all little endian:
 *   0x00  u32  magic 'MDRT' (0x5452444d)
 *   0x04  u32  flags   bit0 = upload the scale table, bit1 = 24bpp output
 *   0x08  u32  rlWords     number of 16-bit run-level words that follow
 *   0x0c  u32  outBytes    expected size of the decoded output
 *   0x10  u8   quant[128]  Y table then UV table
 *   0x90  i16  scale[64]   MDEC(3) scale matrix
 *   0x110 u16  rl[rlWords]
 */

#include <stdint.h>
#include <string.h>

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/pcsxhw.h"
#include "common/kernel/pcdrv.h"
#include "common/syscalls/syscalls.h"

#include "job.h"

#define MDEC0 HW_U32(0x1f801820)
#define MDEC1 HW_U32(0x1f801824)

#define MDEC_CMD_DECODE 0x38000000
#define MDEC_CMD_QUANT 0x40000000
#define MDEC_CMD_SCALE 0x60000000

#define JOB_MAGIC 0x5452444d

static uint8_t s_out[16 * 16 * 3] __attribute__((aligned(4)));
static uint8_t s_quant[128] __attribute__((aligned(4)));
static int16_t s_scale[64] __attribute__((aligned(4)));
static uint16_t s_rl[JOB_RL_WORDS] __attribute__((aligned(4)));

// Every wait here is bounded. An unbounded spin makes a stalled MDEC, a wedged
// emulator and a program that never ran render as exactly the same thing: nothing
// on stdout and no output file.
static int waitIdle(int ch) {
    for (unsigned i = 0; i < 10000000; i++) {
        if ((DMA_CTRL[ch].CHCR & 0x01000000) == 0) return 0;
    }
    ramsyscall_printf("MDRT: DMA%d stuck, CHCR=%08x MDEC1=%08x\n", ch, DMA_CTRL[ch].CHCR, MDEC1);
    return -1;
}

static int dmaWrite(const void *src, unsigned words) {
    if (waitIdle(DMA_MDECIN) < 0) return -1;
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)src;
    DMA_CTRL[DMA_MDECIN].BCR = ((words / 32) << 16) | 32;
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
    return waitIdle(DMA_MDECIN);
}

static int dmaRead(void *dst, unsigned words) {
    if (waitIdle(DMA_MDECOUT) < 0) return -1;
    DMA_CTRL[DMA_MDECOUT].MADR = (uintptr_t)dst;
    DMA_CTRL[DMA_MDECOUT].BCR = ((words / 32) << 16) | 32;
    DMA_CTRL[DMA_MDECOUT].CHCR = 0x01000200;
    return waitIdle(DMA_MDECOUT);
}

static int done(int code) {
    pcsx_exit(code);
    return code;
}

int main() {
    // The job is compiled in rather than read over pcdrv. On the hwtest farm every
    // PCopen returns -1 while PCcreat succeeds, so the read half of PCDRV is not
    // available there and the write half is. Baking the input in costs a rebuild
    // per arm and makes the rig work identically on the farm and in the emulator.
    ramsyscall_printf("MDRT: arm " JOB_ARM ", %d rl words, upload_scale=%d\n", JOB_RL_WORDS,
                      JOB_UPLOAD_SCALE);

    // DMA cannot source from .rodata safely across every setup here; stage into RAM.
    for (unsigned i = 0; i < 128; i++) s_quant[i] = job_quant[i];
    for (unsigned i = 0; i < 64; i++) s_scale[i] = job_scale[i];
    for (unsigned i = 0; i < JOB_RL_WORDS; i++) s_rl[i] = job_rl[i];

    // Enable DMA0 and DMA1. Each channel gets a nibble of DPCR laid out as
    // [enable|prio2..0], so the enable is bit 3 OF THE NIBBLE: 0x77 sets both
    // priorities to 7 and leaves both channels switched off, which presents as
    // DMA0 never clearing its busy bit.
    DPCR |= 0x000000ff;

    MDEC1 = 0x80000000;
    MDEC1 = 0x60000000;

    MDEC0 = MDEC_CMD_QUANT | 1;  // bit0 = colour, so 128 bytes of table follow
    if (dmaWrite(s_quant, 32) < 0) return done(2);

#if JOB_UPLOAD_SCALE
    MDEC0 = MDEC_CMD_SCALE;
    if (dmaWrite(s_scale, 32) < 0) return done(3);
#endif

    const uint32_t decodeWords = (JOB_RL_WORDS + 1) / 2;
    MDEC0 = MDEC_CMD_DECODE | (decodeWords & 0xffff);
    if (dmaWrite(s_rl, decodeWords) < 0) return done(4);
    if (dmaRead(s_out, sizeof(s_out) / 4) < 0) return done(5);

    // Console first, so a result survives even if the artifact path fails.
    ramsyscall_printf("MDRT: status %08x\nMDRT-HEX:", MDEC1);
    for (unsigned i = 0; i < sizeof(s_out); i++) ramsyscall_printf("%02x", s_out[i]);
    ramsyscall_printf("\nMDRT: end\n");

    int r = PCinit();
    (void)r;
    int fd = PCcreat("mdec-out-" JOB_ARM ".bin", 0);
    if (fd >= 0) {
        int w = PCwrite(fd, s_out, sizeof(s_out));
        PCclose(fd);
        ramsyscall_printf("MDRT: wrote %d bytes to mdec-out-" JOB_ARM ".bin\n", w);
    } else {
        ramsyscall_printf("MDRT: PCcreat failed, console hex is the only result\n");
    }
    return done(0);
}
