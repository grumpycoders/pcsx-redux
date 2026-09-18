/*
 * BS decoder rig.
 *
 * Two jobs, in this order, because the second is worthless without the first.
 *
 * 1. A self-test of the GTE leading-zero count the decoder is built on. LZCS/LZCR
 *    is the one corner of the GTE that does not interlock, and the failure is
 *    probabilistic: with one dummy opcode instead of two, the read comes back with
 *    the PREVIOUS write's answer about a third of the time. A single call passes
 *    by luck, and a host parity test cannot see it at all - the host compiles
 *    __builtin_clz. So this sweeps a few thousand values through a tight loop and
 *    compares against a shift-and-count reference, which is the only shape that
 *    exposes it. Build with -DBSDEC_TEST_BREAK_CLZ to confirm the sweep still has
 *    power: that removes one nop and the run must go red.
 *
 * 2. Reads a BS frame over pcdrv, decodes it, writes the run-level halfwords back.
 *    The host side diffs those against supportpsx' fromContainer, which is itself
 *    graded against Sony's DecDCTvlc on the retail corpus. No MDEC and no DMA here
 *    on purpose: this rig answers "does the bitstream decode correctly on real
 *    silicon", and pulling the hardware in would fold two questions together.
 *
 * Runs identically under pcsx-redux and on a devkit. That is the point - the
 * emulator need not model the missing interlock, so the emulator arm passing says
 * nothing about hardware and the two arms have to be compared.
 *
 * ⛔ There is deliberately NO fallback frame. A rig that decodes something built
 * in when its input is missing reports a real-looking result for a run that never
 * happened.
 *
 * Staging, next to the executable:
 *   bs-in.bin    the BS frame, verbatim
 * Produced:
 *   bs-out.bin   16-byte header then the run-level halfwords, little endian
 *     0x00 u32  magic 'BSDR'
 *     0x04 u32  halfwords that follow
 *     0x08 u16  blocks   u8 version  u8 error
 *     0x0c u32  emuId, so a capture says which machine produced it
 */

#include <stdint.h>
#include <string.h>

#include "bsdec/bsdec.h"
#include "common/hardware/pcsxhw.h"
#include "common/kernel/pcdrv.h"
#include "common/syscalls/syscalls.h"

#define MAX_IN (96 * 1024)
#define MAX_HW (64 * 1024)

static uint8_t s_in[MAX_IN] __attribute__((aligned(4)));
static uint16_t s_out[MAX_HW] __attribute__((aligned(4)));

/*
 * Leading zeros by shift and count. Deliberately nothing like the thing it is
 * checking: no GTE, no builtin, no table. A reference that shares a mechanism
 * with its subject agrees with it wherever the mechanism is wrong.
 */
static uint32_t refClz32(uint32_t v) {
    uint32_t n = 0;
    if (v == 0) return 32;
    while ((v & 0x80000000u) == 0) {
        v <<= 1;
        n++;
    }
    return n;
}

#ifdef BSDEC_TEST_BREAK_CLZ
/* One dummy opcode where the hardware wants two. This is the positive control. */
static uint32_t testClz32(uint32_t v) {
    uint32_t r;
    if ((int32_t)v < 0) return 0;
    __asm__ volatile("mtc2 %0, $30\n\tnop" : : "r"(v));
    __asm__ volatile("mfc2 %0, $31\n\tnop\n\tnop" : "=r"(r));
    return r;
}
#else
#define testClz32 bsdecClz32
#endif

/* Returns the number of disagreements, and prints the first few. */
static uint32_t clzSelfTest(void) {
    uint32_t bad = 0, checked = 0, lcg = 0x13579bdfu;

    /* Every single bit, both polarities of the sign question, and zero. The bit-31
     * case is the one a spot-check never uses and the one LZCR gets structurally
     * wrong if the caller does not correct it. */
    for (unsigned i = 0; i < 32; i++) {
        const uint32_t probes[3] = {1u << i, (1u << i) | ((1u << i) - 1u), ~(1u << i)};
        for (unsigned k = 0; k < 3; k++) {
            const uint32_t v = probes[k];
            const uint32_t got = testClz32(v), want = refClz32(v);
            checked++;
            if (got != want) {
                if (bad < 6) ramsyscall_printf("BSDR: clz(%08x) = %d, want %d\n", v, got, want);
                bad++;
            }
        }
    }
    {
        const uint32_t edge[2] = {0u, 0xffffffffu};
        for (unsigned k = 0; k < 2; k++) {
            const uint32_t got = testClz32(edge[k]), want = refClz32(edge[k]);
            checked++;
            if (got != want) {
                if (bad < 6) ramsyscall_printf("BSDR: clz(%08x) = %d, want %d\n", edge[k], got, want);
                bad++;
            }
        }
    }

    /* The interlock arm. Consecutive values must differ a lot, or a stale read
     * returns something close enough to the right answer to pass. The shift makes
     * the leading-zero count itself jump around between iterations. */
    for (unsigned i = 0; i < 20000; i++) {
        uint32_t v;
        lcg = lcg * 1664525u + 1013904223u;
        v = lcg >> (i & 31);
        {
            const uint32_t got = testClz32(v), want = refClz32(v);
            checked++;
            if (got != want) {
                if (bad < 6) ramsyscall_printf("BSDR: clz(%08x) = %d, want %d\n", v, got, want);
                bad++;
            }
        }
    }

    ramsyscall_printf("BSDR-CLZ: checked %d, disagreements %d\n", checked, bad);
    /*
     * ⛔ A green above means NOTHING under an emulator, and this line is the only
     * thing that says so. pcsx-redux computes LZCR synchronously inside MTC2 -
     * gte-transfer.cc, `case 30: d[31].d = countLeadingBits(value)` - so there is
     * no pending write for a too-early MFC2 to catch, and the store delay the CPU
     * chapter documents is simply absent. Measured 2026-09-18: this rig built with
     * -DBSDEC_TEST_BREAK_CLZ, i.e. one dummy opcode where the hardware wants two,
     * passes with zero disagreements in the emulator. Only the hardware arm can
     * fail this, so a clean emulator run is not evidence the nops are right.
     */
    if (*((volatile uint32_t *const)0x1f802080) == 0x58534350) {
        ramsyscall_printf("BSDR-CLZ: emulated, and the GTE store delay is not modelled here - "
                          "this sweep cannot fail on this host. Hardware is the arm that counts.\n");
    }
    /* A sweep that examined nothing must not read as a pass. */
    if (checked < 20000) {
        ramsyscall_printf("BSDR: the clz sweep examined %d values, which is not the sweep\n", checked);
        return checked + 1;
    }
    return bad;
}

static int done(int code) {
    pcsx_exit(code);
    return code;
}

int main() {
    uint32_t inBytes = 0, need;
    struct BsdecResult r;
    int fd;

    if (clzSelfTest() != 0) {
        ramsyscall_printf("BSDR: the leading-zero count is wrong on this machine, so nothing below means anything\n");
        return done(20);
    }

    PCinit();
    fd = PCopen("bs-in.bin", 0, 0);
    if (fd < 0) fd = PCopen("BS-IN.BIN", 0, 0);
    if (fd < 0) {
        ramsyscall_printf("BSDR: no frame. Stage bs-in.bin next to the executable.\n");
        return done(10);
    }
    for (;;) {
        const int got = PCread(fd, s_in + inBytes, (int)(MAX_IN - inBytes));
        if (got <= 0) break;
        inBytes += (uint32_t)got;
        if (inBytes == MAX_IN) break;
    }
    PCclose(fd);
    if (inBytes < 8) {
        ramsyscall_printf("BSDR: read %d bytes, not even a header\n", inBytes);
        return done(11);
    }

    need = bsdecRlHalfwords(s_in, inBytes);
    if (need == 0 || need > MAX_HW) {
        ramsyscall_printf("BSDR: frame wants %d halfwords, this rig holds %d\n", need, MAX_HW);
        return done(12);
    }
    r = bsdecFrame(s_in, inBytes, s_out, need);
    ramsyscall_printf("BSDR: in %d bytes, ver %d, q %d, blocks %d, halfwords %d, err %d, cmd %08x\n", inBytes,
                      r.version, r.qScale, r.blocks, r.halfwords, r.error, r.mdecCommand);
    if (r.error != BSDEC_OK && r.error != BSDEC_TRUNCATED) return done(13);

    {
        uint8_t hdr[16];
        const uint32_t emuId = *((volatile uint32_t *const)0x1f802080);
        hdr[0] = 'B';
        hdr[1] = 'S';
        hdr[2] = 'D';
        hdr[3] = 'R';
        hdr[4] = (uint8_t)r.halfwords;
        hdr[5] = (uint8_t)(r.halfwords >> 8);
        hdr[6] = (uint8_t)(r.halfwords >> 16);
        hdr[7] = (uint8_t)(r.halfwords >> 24);
        hdr[8] = (uint8_t)r.blocks;
        hdr[9] = (uint8_t)(r.blocks >> 8);
        hdr[10] = r.version;
        hdr[11] = r.error;
        hdr[12] = (uint8_t)emuId;
        hdr[13] = (uint8_t)(emuId >> 8);
        hdr[14] = (uint8_t)(emuId >> 16);
        hdr[15] = (uint8_t)(emuId >> 24);
        fd = PCcreat("bs-out.bin", 0);
        if (fd < 0) {
            ramsyscall_printf("BSDR: PCcreat failed, no artifact\n");
            return done(14);
        }
        PCwrite(fd, hdr, sizeof(hdr));
        PCwrite(fd, s_out, (int)(r.halfwords * 2));
        PCclose(fd);
        ramsyscall_printf("BSDR: wrote %d halfwords\nBSDR: end\n", r.halfwords);
    }
    return done(0);
}
