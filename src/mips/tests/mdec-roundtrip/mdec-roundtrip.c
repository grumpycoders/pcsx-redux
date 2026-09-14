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

#define MDEC0 HW_U32(0x1f801820)
#define MDEC1 HW_U32(0x1f801824)

#define MDEC_CMD_DECODE 0x38000000
#define MDEC_CMD_QUANT 0x40000000
#define MDEC_CMD_SCALE 0x60000000

#define JOB_MAGIC 0x5452444d

static uint8_t s_job[262144] __attribute__((aligned(4)));
static uint8_t s_out[131072] __attribute__((aligned(4)));

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

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
    int r = PCinit();
    if (r != 0) {
        ramsyscall_printf("MDRT: PCinit failed: %d\n", r);
        return done(1);
    }

    int fd = PCopen("mdec-in.bin", 0, 0);
    if (fd < 0) {
        ramsyscall_printf("MDRT: cannot open mdec-in.bin\n");
        return done(1);
    }
    int got = PCread(fd, s_job, sizeof(s_job));
    PCclose(fd);
    if (got < 0x110) {
        ramsyscall_printf("MDRT: short job file: %d\n", got);
        return done(1);
    }
    if (rd32(s_job) != JOB_MAGIC) {
        ramsyscall_printf("MDRT: bad magic %08x\n", rd32(s_job));
        return done(1);
    }

    const uint32_t flags = rd32(s_job + 4);
    const uint32_t rlWords = rd32(s_job + 8);
    const uint32_t outBytes = rd32(s_job + 12);
    if (outBytes > sizeof(s_out)) {
        ramsyscall_printf("MDRT: outBytes %u too large\n", outBytes);
        return done(1);
    }

    // Enable DMA0 and DMA1. Each channel gets a nibble of DPCR laid out as
    // [enable|prio2..0], so the enable is bit 3 OF THE NIBBLE: 0x77 sets both
    // priorities to 7 and leaves both channels switched off, which presents as
    // DMA0 never clearing its busy bit.
    DPCR |= 0x000000ff;

    // Reset, then enable both DMA directions. Bit31 reset, bit30 DMA0 enable,
    // bit29 DMA1 enable.
    MDEC1 = 0x80000000;
    MDEC1 = 0x60000000;

    MDEC0 = MDEC_CMD_QUANT | 1;  // bit0 = colour, so 128 bytes of table follow
    if (dmaWrite(s_job + 0x10, 32) < 0) return done(2);

    if (flags & 1) {
        MDEC0 = MDEC_CMD_SCALE;
        if (dmaWrite(s_job + 0x90, 32) < 0) return done(3);
    }

    const uint32_t decodeWords = (rlWords + 1) / 2;
    MDEC0 = MDEC_CMD_DECODE | (flags & 2 ? 0x08000000 : 0) | (decodeWords & 0xffff);
    if (dmaWrite(s_job + 0x110, decodeWords) < 0) return done(4);
    if (dmaRead(s_out, outBytes / 4) < 0) return done(5);

    fd = PCcreat("mdec-out.bin", 0);
    if (fd < 0) {
        ramsyscall_printf("MDRT: cannot create mdec-out.bin\n");
        return done(1);
    }
    r = PCwrite(fd, s_out, outBytes);
    PCclose(fd);
    ramsyscall_printf("MDRT: wrote %d of %u bytes, status %08x\n", r, outBytes, MDEC1);
    return done(r == (int)outBytes ? 0 : 6);
}
