/*
 * MDEC roundtrip rig.
 *
 * Reads a job file over pcdrv, pushes it through the real MDEC, writes the
 * decoded output back over pcdrv. Runs identically under pcsx-redux and on a
 * devkit, which is the point: the same binary and the same job file give an
 * emulator arm and a hardware arm that differ in nothing but the silicon.
 *
 * Job file layout, all little endian. Written by genjob.py, which owns the arm
 * definitions; this file owns the parsing and validates every field it uses.
 *   0x00  u32  magic 'MDRT' (0x5452444d)
 *   0x04  u32  flags       bit0 = upload the scale table
 *   0x08  u32  rlWords     number of 16-bit run-level words that follow
 *   0x0c  u32  outBytes    expected size of the decoded output
 *   0x10  u32  resetMode   0 none, 1 reset only, 2 +quant, 3 +scale, 4 +both
 *   0x14  char arm[12]     NUL-padded; names the run and the output file
 *   0x20  u8   quant[128]  Y table then UV table
 *   0xa0  i16  scale[64]   MDEC(3) scale matrix
 *   0x120 u16  rl[rlWords]
 *
 * The job was compiled in until 2026-09-18, which meant the guest binary changed
 * per arm and a generated header was tracked in git. It is read at runtime now,
 * so one build serves every arm. ⛔ There is deliberately NO fallback job: a rig
 * that quietly decodes a default when its input is missing reports a real-looking
 * result for an experiment that never ran.
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

// MDEC(1): bits 31-29 = command 1, bits 28-27 = output depth (0=4bit, 1=8bit,
// 2=24bit, 3=15bit). 0x38000000 sets depth 3, i.e. 15-bit, which is what STR
// video actually uses and is NOT what this rig wants. 24-bit is depth 2.
#define MDEC_CMD_DECODE 0x30000000
#define MDEC_CMD_QUANT 0x40000000
#define MDEC_CMD_SCALE 0x60000000

#define JOB_HEADER 0x20
#define ARM_FIELD 12
// Must match genjob.py's MAX_RL_WORDS. It refuses to emit a larger job and this
// refuses to load one, so the bound is stated on both sides of the file.
#define MAX_RL_WORDS 4096

static uint8_t s_out[16 * 16 * 3] __attribute__((aligned(4)));
static uint8_t s_quant[128] __attribute__((aligned(4)));
static int16_t s_scale[64] __attribute__((aligned(4)));
static uint16_t s_rl[MAX_RL_WORDS] __attribute__((aligned(4)));
static char s_arm[ARM_FIELD + 1];
static uint32_t s_flags, s_rlWords, s_resetMode;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// PCread is allowed to return short. Looping is the difference between a truncated
// job that decodes garbage and one that says so.
static int readExact(int fd, void *buf, int len, const char *what) {
    uint8_t *p = (uint8_t *)buf;
    int left = len;
    while (left > 0) {
        int got = PCread(fd, p, left);
        if (got <= 0) {
            ramsyscall_printf("MDRT: short read on %s, %d of %d bytes missing (PCread -> %d)\n", what, left, len, got);
            return -1;
        }
        p += got;
        left -= got;
    }
    return 0;
}

// Returns 0 on success. Every failure path prints what it was and why, because the
// one thing this must never do is proceed with a job it did not fully read.
static int loadJob(void) {
    // Both cases of the same name, so a farm that stages uppercase still runs.
    // Staging is lowercase and that is what normally opens.
    // ⚠ This does NOT answer whether the lookup is case INSENSITIVE, and the probe
    // it replaced did: that one tried both names unconditionally, this one stops at
    // the first success. It is a fallback, not a measurement. If the case question
    // matters again, it needs its own arm rather than a reading taken off this log.
    static const char *const names[] = {"mdec-in.bin", "MDEC-IN.BIN"};
    int fd = -1;
    for (unsigned i = 0; i < 2 && fd < 0; i++) {
        fd = PCopen(names[i], 0, 0);
        ramsyscall_printf("MDRT: PCopen(%s) -> %d\n", names[i], fd);
    }
    if (fd < 0) {
        ramsyscall_printf("MDRT: no job file. Stage mdec-in.bin next to the executable.\n");
        return -1;
    }

    uint8_t hdr[JOB_HEADER] __attribute__((aligned(4)));
    if (readExact(fd, hdr, sizeof(hdr), "header") < 0) goto fail;
    if (hdr[0] != 'M' || hdr[1] != 'D' || hdr[2] != 'R' || hdr[3] != 'T') {
        ramsyscall_printf("MDRT: bad magic %02x%02x%02x%02x, not an MDRT job\n", hdr[0], hdr[1], hdr[2], hdr[3]);
        goto fail;
    }
    s_flags = le32(hdr + 4);
    s_rlWords = le32(hdr + 8);
    const uint32_t outBytes = le32(hdr + 12);
    s_resetMode = le32(hdr + 16);
    memcpy(s_arm, hdr + 0x14, ARM_FIELD);
    s_arm[ARM_FIELD] = 0;

    if (s_rlWords == 0 || s_rlWords > MAX_RL_WORDS) {
        ramsyscall_printf("MDRT: rlWords %d out of range 1..%d\n", s_rlWords, MAX_RL_WORDS);
        goto fail;
    }
    // The output size is fixed by the DMA below, so a job asking for a different
    // one is a job built against a different rig.
    if (outBytes != sizeof(s_out)) {
        ramsyscall_printf("MDRT: job wants %d output bytes, this rig produces %d\n", outBytes, sizeof(s_out));
        goto fail;
    }

    if (readExact(fd, s_quant, sizeof(s_quant), "quant") < 0) goto fail;
    if (readExact(fd, s_scale, sizeof(s_scale), "scale") < 0) goto fail;
    if (readExact(fd, s_rl, s_rlWords * 2, "rl") < 0) goto fail;
    PCclose(fd);
    return 0;

fail:
    PCclose(fd);
    return -1;
}

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
    // pcdrv first: the job is an input now, so a failure here has to stop the run
    // before any of it looks like a result.
    int r = PCinit();
    (void)r;
    if (loadJob() < 0) return done(10);

    // The load lands the tables straight into .bss, which is where DMA needs them
    // anyway - the old build staged them out of .rodata by hand for that reason.
    ramsyscall_printf("MDRT: arm %s, %d rl words, upload_scale=%d, reset_mode=%d\n", s_arm, s_rlWords, s_flags & 1,
                      s_resetMode);

    // Enable DMA0 and DMA1. Each channel gets a nibble of DPCR laid out as
    // [enable|prio2..0], so the enable is bit 3 OF THE NIBBLE: 0x77 sets both
    // priorities to 7 and leaves both channels switched off, which presents as
    // DMA0 never clearing its busy bit.
    DPCR |= 0x000000ff;

    MDEC1 = 0x80000000;
    MDEC1 = 0x60000000;

    MDEC0 = MDEC_CMD_QUANT | 1;  // bit0 = colour, so 128 bytes of table follow
    if (dmaWrite(s_quant, 32) < 0) return done(2);

    if (s_flags & 1) {
        MDEC0 = MDEC_CMD_SCALE;
        if (dmaWrite(s_scale, 32) < 0) return done(3);
    }

    // The decode transfer CANNOT be serialised in front of the output transfer.
    // Once the MDEC has a block ready it stops asserting Data-In Request, so DMA0
    // never completes until DMA1 drains it: waiting for DMA0 and only then
    // starting DMA1 deadlocks on real silicon. pcsx-redux does not deadlock here,
    // because its dma0 stashes the request in pending_dma1 and runs it for you, so
    // a serialised version passes in the emulator and hangs on hardware.
    if (s_resetMode) {
        // Does a reset clear the uploaded tables? Reset is documented as setting
        // status to 80040000h and says nothing about the matrices, so this is a
        // measurement rather than a lookup. The DMA request enables DO get cleared,
        // hence the second write: that part is the sequence, not the question.
        MDEC1 = 0x80000000;
        MDEC1 = 0x60000000;
        if (s_resetMode == 2 || s_resetMode == 4) {
            MDEC0 = MDEC_CMD_QUANT | 1;
            if (dmaWrite(s_quant, 32) < 0) return done(8);
        }
        if (s_resetMode == 3 || s_resetMode == 4) {
            MDEC0 = MDEC_CMD_SCALE;
            if (dmaWrite(s_scale, 32) < 0) return done(9);
        }
    }

    const uint32_t decodeWords = (s_rlWords + 1) / 2;
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

    // The read-half probe that used to sit here is gone: loadJob() exercises the
    // same path for real at startup, so a run that got this far has already proven
    // PCopen and PCread work and which spelling of the name the lookup accepts.
    char outName[10 + ARM_FIELD + 5];
    strcpy(outName, "mdec-out-");
    strcat(outName, s_arm);
    strcat(outName, ".bin");
    int fd = PCcreat(outName, 0);
    if (fd >= 0) {
        int w = PCwrite(fd, s_out, sizeof(s_out));
        PCclose(fd);
        ramsyscall_printf("MDRT: wrote %d bytes to %s\n", w, outName);
    } else {
        ramsyscall_printf("MDRT: PCcreat(%s) failed, console hex is the only result\n", outName);
    }
    return done(0);
}
