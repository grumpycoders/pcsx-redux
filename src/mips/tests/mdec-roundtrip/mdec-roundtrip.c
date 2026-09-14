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

// MDEC(1): bits 31-29 = command 1, bits 28-27 = output depth (0=4bit, 1=8bit,
// 2=24bit, 3=15bit). 0x38000000 sets depth 3, i.e. 15-bit, which is what STR
// video actually uses and is NOT what this rig wants. 24-bit is depth 2.
#define MDEC_CMD_DECODE 0x30000000
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
static int waitIdle(int ch, const char *site) {
    for (unsigned i = 0; i < 10000000; i++) {
        if ((DMA_CTRL[ch].CHCR & 0x01000000) == 0) return 0;
    }
    // One slot per outcome: without the site tag, four different stalls render as
    // the same line and the status word has to carry the whole diagnosis alone.
    ramsyscall_printf("MDRT: DMA%d stuck at %s, CHCR=%08x BCR=%08x MDEC1=%08x\n", ch, site,
                      DMA_CTRL[ch].CHCR, DMA_CTRL[ch].BCR, MDEC1);
    return -1;
}

static void startWrite(const void *src, unsigned words) {
    DMA_CTRL[DMA_MDECIN].MADR = (uintptr_t)src;
    DMA_CTRL[DMA_MDECIN].BCR = ((words / 32) << 16) | 32;
    DMA_CTRL[DMA_MDECIN].CHCR = 0x01000201;
}

static void startRead(void *dst, unsigned words) {
    DMA_CTRL[DMA_MDECOUT].MADR = (uintptr_t)dst;
    DMA_CTRL[DMA_MDECOUT].BCR = ((words / 32) << 16) | 32;
    DMA_CTRL[DMA_MDECOUT].CHCR = 0x01000200;
}

static int dmaWrite(const void *src, unsigned words) {
    if (waitIdle(DMA_MDECIN, "pre-write") < 0) return -1;
    startWrite(src, words);
    return waitIdle(DMA_MDECIN, "post-write");
}

static int done(int code) {
    pcsx_exit(code);
    return code;
}

int main() {
    // The job is compiled in rather than read over pcdrv, which makes a run
    // self-contained and identical under the emulator and on the farm. It is NOT
    // because PCDRV reads are unavailable: that was an early misdiagnosis of an
    // empty asset directory on the runner side, since fixed.
    ramsyscall_printf("MDRT: arm " JOB_ARM " build 1789414538, %d rl words, upload_scale=%d\n", JOB_RL_WORDS,
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

    // The decode transfer CANNOT be serialised in front of the output transfer.
    // Once the MDEC has a block ready it stops asserting Data-In Request, so DMA0
    // never completes until DMA1 drains it: waiting for DMA0 and only then
    // starting DMA1 deadlocks on real silicon. pcsx-redux does not deadlock here,
    // because its dma0 stashes the request in pending_dma1 and runs it for you, so
    // a serialised version passes in the emulator and hangs on hardware.
#if JOB_RESET_MODE
    // Does a reset clear the uploaded tables? Reset is documented as setting
    // status to 80040000h and says nothing about the matrices, so this is a
    // measurement rather than a lookup. The DMA request enables DO get cleared,
    // hence the second write: that part is the sequence, not the question.
    MDEC1 = 0x80000000;
    MDEC1 = 0x60000000;
#if JOB_RESET_MODE == 2 || JOB_RESET_MODE == 4
    MDEC0 = MDEC_CMD_QUANT | 1;
    if (dmaWrite(s_quant, 32) < 0) return done(8);
#endif
#if JOB_RESET_MODE == 3 || JOB_RESET_MODE == 4
    MDEC0 = MDEC_CMD_SCALE;
    if (dmaWrite(s_scale, 32) < 0) return done(9);
#endif
#endif

    const uint32_t decodeWords = (JOB_RL_WORDS + 1) / 2;
    MDEC0 = MDEC_CMD_DECODE | (decodeWords & 0xffff);
    if (waitIdle(DMA_MDECIN, "pre-decode") < 0) return done(4);
    if (waitIdle(DMA_MDECOUT, "pre-read") < 0) return done(5);
    startWrite(s_rl, decodeWords);
    startRead(s_out, sizeof(s_out) / 4);
    if (waitIdle(DMA_MDECOUT, "post-read") < 0) return done(6);
    if (waitIdle(DMA_MDECIN, "post-decode") < 0) return done(7);

    // Console first, so a result survives even if the artifact path fails.
    ramsyscall_printf("MDRT: status %08x\nMDRT-HEX:", MDEC1);
    for (unsigned i = 0; i < sizeof(s_out); i++) ramsyscall_printf("%02x", s_out[i]);
    ramsyscall_printf("\nMDRT: end\n");

    int r = PCinit();
    (void)r;
    // Probe the READ half as well. Attach any asset as `mdec-in.bin` and this
    // reports whether a console can actually read it back, which is the one thing
    // the farm-side fix is not yet verified on.
    {
        int pf = PCopen("mdec-in.bin", 0, 0);
        ramsyscall_printf("MDRT: PCopen(mdec-in.bin) -> %d\n", pf);
        if (pf >= 0) {
            uint8_t probe[16];
            memset(probe, 0, sizeof(probe));
            int got = PCread(pf, probe, sizeof(probe));
            PCclose(pf);
            ramsyscall_printf("MDRT: PCread -> %d, bytes %02x %02x %02x %02x\n", got, probe[0], probe[1], probe[2],
                              probe[3]);
        }
    }
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
