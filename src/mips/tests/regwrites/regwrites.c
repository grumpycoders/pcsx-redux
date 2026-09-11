/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

/*
 * MMIO partial-word write masking probe.
 *
 * Hypothesis: the PS1's on-die MMIO decoders (IRQ control, DMA, timers, GPU)
 * ignore the CPU's byte-enable signals, so an `sb` to a 32-bit register
 * latches whatever is on the bus rather than just the addressed byte. The SPU
 * sits behind an external SBUS that is known to honor width signals
 * end-to-end - it's the natural control group.
 *
 * Methodology: for each (target register, op, byte offset, baseline pattern,
 * source pattern) tuple, write the baseline via the natural-width store, then
 * execute the test op via an asm trampoline (asm.s, so the compiler cannot
 * legalize it), then read back. Print parseable lines: the human classifies
 * the readback patterns.
 *
 * Round 1: sw / sb / sh at aligned offsets.
 * Round 2: swl / swr at all four offsets, plus sh at misaligned offsets +1
 * and +3 (which should AdES). The cop0 exception handler from
 * ../cop0/exceptions.cpp is wired in to skip the faulting instruction so a
 * misaligned probe does not abort the run.
 */

#include <stdint.h>

#include "common/hardware/counters.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

extern void rw_sb(uint32_t addr, uint32_t off, uint32_t value);
extern void rw_sh(uint32_t addr, uint32_t off, uint32_t value);
extern void rw_sw(uint32_t addr, uint32_t off, uint32_t value);
extern void rw_swl(uint32_t addr, uint32_t off, uint32_t value);
extern void rw_swr(uint32_t addr, uint32_t off, uint32_t value);

extern void installExceptionHandlers(uint32_t (*handler)(uint32_t *regs, uint32_t from));
extern void uninstallExceptionHandlers();

typedef enum { OP_SB, OP_SH, OP_SW, OP_SWL, OP_SWR } op_t;

static const char *opname(op_t op) {
    switch (op) {
        case OP_SB: return "sb ";
        case OP_SH: return "sh ";
        case OP_SW: return "sw ";
        case OP_SWL: return "swl";
        case OP_SWR: return "swr";
    }
    return "???";
}

typedef struct {
    const char *name;
    uint32_t addr;
    int width;   /* register width in bits: 16 or 32 */
    int onSbus;  /* 1 = behind SBUS (control group), 0 = on-die MMIO */
} target_t;

/* R/W targets with no destructive side effects:
 *   IMASK / DPCR  - 32-bit, on-die, R/W. Saved/restored.
 *   SPU_MAINVOL_L - 16-bit, SBUS, R/W after muteSpu().
 *   SPU_V0_VOL_L  - 16-bit, SBUS, voice volume in the voice struct. */
static const target_t targets[] = {
    {"IMASK",          0xbf801074, 32, 0},
    {"DPCR",           0xbf8010f0, 32, 0},
    {"SPU_MAINVOL_L",  0xbf801d80, 16, 1},
    {"SPU_V0_VOL_L",   0xbf801c00, 16, 1},
};
#define NUM_TARGETS (sizeof(targets) / sizeof(targets[0]))

static const uint32_t baselines[] = {0x00000000u, 0xFFFFFFFFu, 0x11223344u};
#define NUM_BASELINES (sizeof(baselines) / sizeof(baselines[0]))

static const uint32_t sources[] = {0xAABBCCDDu, 0xFEDCBA98u};
#define NUM_SOURCES (sizeof(sources) / sizeof(sources[0]))

/* Exception-handler shared state. The handler runs with interrupts in their
 * pre-trap state (no nesting expected on this single-threaded test). */
static volatile int g_exc_fired;
static volatile uint32_t g_exc_epc;
static volatile uint32_t g_exc_cause;
static volatile uint32_t g_exc_badvaddr;

static uint32_t exc_handler(uint32_t *regs, uint32_t from) {
    (void)regs;
    (void)from;
    uint32_t cause, epc, badvaddr;
    /* nops after mfc0 to satisfy the cop0 read-load delay */
    __asm__ volatile("mfc0 %0, $13\nnop" : "=r"(cause));
    __asm__ volatile("mfc0 %0, $14\nnop" : "=r"(epc));
    __asm__ volatile("mfc0 %0, $8\nnop" : "=r"(badvaddr));
    g_exc_fired = 1;
    g_exc_epc = epc;
    g_exc_cause = cause;
    g_exc_badvaddr = badvaddr;
    /* Skip the faulting instruction. The trampolines are simple enough that
     * EPC is never in a branch delay slot - the store is in the body, not
     * after a branch. */
    return epc + 4;
}

static void set_baseline(const target_t *t, uint32_t value) {
    if (t->width == 32) {
        *(volatile uint32_t *)(t->addr) = value;
    } else {
        *(volatile uint16_t *)(t->addr) = (uint16_t)value;
    }
}

static uint32_t readback(const target_t *t) {
    if (t->width == 32) {
        return *(volatile uint32_t *)(t->addr);
    } else {
        return (uint32_t) * (volatile uint16_t *)(t->addr);
    }
}

static uint32_t readback_neighbor(const target_t *t) {
    if (t->onSbus && t->width == 16) {
        return (uint32_t) * (volatile uint16_t *)(t->addr + 2);
    }
    return 0xFFFFFFFFu;
}

static void do_op(op_t op, uint32_t addr, uint32_t off, uint32_t value) {
    switch (op) {
        case OP_SB:  rw_sb(addr, off, value); break;
        case OP_SH:  rw_sh(addr, off, value); break;
        case OP_SW:  rw_sw(addr, off, value); break;
        case OP_SWL: rw_swl(addr, off, value); break;
        case OP_SWR: rw_swr(addr, off, value); break;
    }
}

static void probe(const target_t *t, op_t op, uint32_t off, uint32_t baseline, uint32_t src) {
    uint32_t neighbor_baseline = 0;
    if (t->onSbus && t->width == 16) {
        neighbor_baseline = (uint16_t)baseline;
        *(volatile uint16_t *)(t->addr + 2) = (uint16_t)neighbor_baseline;
    }
    set_baseline(t, baseline);

    g_exc_fired = 0;
    do_op(op, t->addr, off, src);

    if (g_exc_fired) {
        ramsyscall_printf("%-15s %s +%d base=0x%08x src=0x%08x AdES cause=0x%08x epc=0x%08x badvaddr=0x%08x\n",
                          t->name, opname(op), (int)off, baseline, src,
                          g_exc_cause, g_exc_epc, g_exc_badvaddr);
        return;
    }

    uint32_t got = readback(t);
    uint32_t neigh = readback_neighbor(t);

    if (neigh != 0xFFFFFFFFu) {
        ramsyscall_printf("%-15s %s +%d base=0x%08x src=0x%08x got=0x%04x neigh=0x%04x\n",
                          t->name, opname(op), (int)off, baseline, src, got, neigh);
    } else {
        ramsyscall_printf("%-15s %s +%d base=0x%08x src=0x%08x got=0x%08x\n",
                          t->name, opname(op), (int)off, baseline, src, got);
    }
}

int main() {
    int wasOn = enterCriticalSection();

    /* Save state we'll be smashing. */
    uint32_t oldIMASK = IMASK;
    uint32_t oldDPCR = DPCR;
    uint16_t oldMainL = SPU_VOL_MAIN_LEFT;
    uint16_t oldMainR = SPU_VOL_MAIN_RIGHT;
    uint16_t oldRevL = SPU_REVERB_LEFT;
    uint16_t oldRevR = SPU_REVERB_RIGHT;
    uint16_t oldV0VolL = SPU_VOICES[0].volumeLeft;
    uint16_t oldV0VolR = SPU_VOICES[0].volumeRight;

    muteSpu();

    /* Install our exception handler. Required for the misaligned-sh probes:
     * sh at +1 / +3 will AdES, and we want to record that and continue. */
    installExceptionHandlers(exc_handler);
    syscall_flushCache();

    ramsyscall_printf("=== PS1 MMIO Partial-Word Write Masking Probe ===\n");
    ramsyscall_printf("Compiled: %s %s\n", __DATE__, __TIME__);
    ramsyscall_printf("Format:\n");
    ramsyscall_printf("  <reg> <op>  +<off> base=<seed> src=<src> got=<readback>");
    ramsyscall_printf(" [neigh=<next-reg>]\n");
    ramsyscall_printf("  AdES rows: faulting instruction trapped (cause/epc/badvaddr).\n\n");

    for (unsigned ti = 0; ti < NUM_TARGETS; ti++) {
        const target_t *t = &targets[ti];
        ramsyscall_printf("--- %s @ 0x%08x (%s, %d-bit) ---\n",
                          t->name, t->addr, t->onSbus ? "SBUS" : "on-die", t->width);

        for (unsigned bi = 0; bi < NUM_BASELINES; bi++) {
            uint32_t base = baselines[bi];
            for (unsigned si = 0; si < NUM_SOURCES; si++) {
                uint32_t src = sources[si];

                if (t->width == 32) {
                    /* Round 1: positive control + sb at every offset + sh aligned. */
                    probe(t, OP_SW, 0, base, src);
                    for (int off = 0; off < 4; off++) {
                        probe(t, OP_SB, off, base, src);
                    }
                    probe(t, OP_SH, 0, base, src);
                    probe(t, OP_SH, 2, base, src);

                    /* Round 2: misaligned sh - expected to AdES. */
                    probe(t, OP_SH, 1, base, src);
                    probe(t, OP_SH, 3, base, src);

                    /* Round 2: swl / swr at every byte offset. */
                    for (int off = 0; off < 4; off++) {
                        probe(t, OP_SWL, off, base, src);
                    }
                    for (int off = 0; off < 4; off++) {
                        probe(t, OP_SWR, off, base, src);
                    }
                } else {
                    /* 16-bit SBUS: keep round 1 set, plus swl/swr probes
                     * at every offset. The +2/+3 cases are interesting
                     * because the byte count varies (1 to 4 bytes) and
                     * the access may straddle a halfword boundary - the
                     * BIU has to map a CPU 32-bit driven word to one or
                     * two 16-bit SBUS transactions. */
                    probe(t, OP_SH, 0, base, src);
                    probe(t, OP_SB, 0, base, src);
                    probe(t, OP_SB, 1, base, src);
                    probe(t, OP_SB, 2, base, src);
                    probe(t, OP_SB, 3, base, src);
                    probe(t, OP_SWL, 0, base, src);
                    probe(t, OP_SWL, 1, base, src);
                    probe(t, OP_SWL, 2, base, src);
                    probe(t, OP_SWL, 3, base, src);
                    probe(t, OP_SWR, 0, base, src);
                    probe(t, OP_SWR, 1, base, src);
                    probe(t, OP_SWR, 2, base, src);
                    probe(t, OP_SWR, 3, base, src);
                }
            }
        }
        ramsyscall_printf("\n");
    }

    uninstallExceptionHandlers();
    syscall_flushCache();

    IMASK = oldIMASK;
    DPCR = oldDPCR;
    SPU_VOICES[0].volumeLeft = oldV0VolL;
    SPU_VOICES[0].volumeRight = oldV0VolR;
    SPU_REVERB_LEFT = oldRevL;
    SPU_REVERB_RIGHT = oldRevR;
    SPU_VOL_MAIN_LEFT = oldMainL;
    SPU_VOL_MAIN_RIGHT = oldMainR;

    if (wasOn) leaveCriticalSection();

    ramsyscall_printf("=== Done ===\n");
    while (1)
        ;
    return 0;
}
