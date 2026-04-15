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

#ifndef PCSX_TESTS
#define PCSX_TESTS 0
#endif

#if PCSX_TESTS
#define CESTER_MAYBE_TEST CESTER_SKIP_TEST
#else
#define CESTER_MAYBE_TEST CESTER_TEST
#endif

#include "common/hardware/counters.h"
#include "common/hardware/gpu.h"
#include "common/hardware/hwregs.h"
#include "common/syscalls/syscalls.h"

#undef unix
#define CESTER_NO_SIGNAL
#define CESTER_NO_TIME
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#include "exotic/cester.h"

// clang-format off

#define BUSY_WAIT(n) do { for (int _bw = (n); _bw > 0; _bw--) __asm__ volatile(""); } while(0)

CESTER_BODY(
static int s_interruptsWereEnabled;
)

CESTER_BEFORE_ALL(timer_tests,
    s_interruptsWereEnabled = enterCriticalSection();
    IMASK = 0;
    IREG = 0;
)

CESTER_AFTER_ALL(timer_tests,
    if (s_interruptsWereEnabled) leaveCriticalSection();
)

CESTER_BODY(
static void waitVSync(void) {
    while (!(GPU_STATUS & 0x80000000)) __asm__ volatile("");
    while (GPU_STATUS & 0x80000000) __asm__ volatile("");
}
)

/* =================================================================
 * Target reset: counter reaches target value, then resets.
 * The target value IS briefly visible on reads.
 * With target=N, reset-on-target: counter counts 0..N, then resets.
 * The hit-target flag (bit 11) should be set after target is reached.
 * ================================================================= */
CESTER_TEST(timerTargetResetHitsTarget, timer_tests,
    COUNTERS[2].target = 0x0010;
    COUNTERS[2].mode = TM_RESET_TARGET;
    BUSY_WAIT(500);

    uint16_t mode = COUNTERS[2].mode;
    /* Hit-target flag should be set after counter reached target */
    cester_assert_cmp((int)(mode & TM_HIT_TARGET), !=, 0);
)

/* Counter with reset-on-target should not overflow (bit 12 stays clear)
 * if target is well below 0xFFFF. */
CESTER_TEST(timerTargetResetNoOverflow, timer_tests,
    COUNTERS[2].target = 0x0010;
    COUNTERS[2].mode = TM_RESET_TARGET;
    BUSY_WAIT(500);

    uint16_t mode = COUNTERS[2].mode;
    /* Overflow flag should NOT be set - counter resets at target */
    cester_assert_int_eq(0, (int)(mode & TM_HIT_OVERFLOW));
)

/* =================================================================
 * Sysclock/8 divider ratio.
 * Run both clock modes with same delay, ratio should be ~8.
 * ================================================================= */
CESTER_TEST(timerSysclockDiv8Ratio, timer_tests,
    /* Use a short delay to avoid 16-bit counter wrap on sysclock.
     * At ~33MHz sysclock, 1000 loop iters ~ a few thousand counts. */

    /* Sysclock/8 mode first (slower, won't wrap) */
    COUNTERS[2].target = 0xFFFF;
    COUNTERS[2].mode = TM_CLK_DIV8;
    BUSY_WAIT(1000);
    uint16_t div8_val = COUNTERS[2].value;

    /* Sysclock mode */
    COUNTERS[2].target = 0xFFFF;
    COUNTERS[2].mode = 0;
    BUSY_WAIT(1000);
    uint16_t sys_val = COUNTERS[2].value;

    /* Ratio should be close to 8 (allow 6-10 for measurement jitter) */
    int ratio = sys_val / (div8_val ? div8_val : 1);
    cester_assert_cmp(ratio, >=, 6);
    cester_assert_cmp(ratio, <=, 10);
)

/* =================================================================
 * Mode write resets counter to 0.
 * ================================================================= */
CESTER_TEST(timerModeWriteResetsCounter, timer_tests,
    /* Warmup pass to prime icache */
    COUNTERS[2].mode = 0;
    COUNTERS[2].target = 0xFFFF;
    BUSY_WAIT(50000);
    (void)COUNTERS[2].value;
    COUNTERS[2].mode = 0;
    (void)COUNTERS[2].value;

    /* Real measurement */
    COUNTERS[2].mode = 0;
    COUNTERS[2].target = 0xFFFF;
    BUSY_WAIT(50000);

    uint16_t before = COUNTERS[2].value;
    cester_assert_cmp((int)before, >, 0);

    /* Write mode - should reset to 0 */
    COUNTERS[2].mode = 0;
    int after = COUNTERS[2].value;

    /* Counter restarts immediately after reset, so a few ticks
     * may elapse before the read. Allow small tolerance. */
    cester_assert_cmp(after, <, 10);
)

/* =================================================================
 * Status bits: hit-target (bit 11) set on target, cleared on read.
 * ================================================================= */
CESTER_TEST(timerHitTargetFlagSetAndCleared, timer_tests,
    /* Warmup pass to prime icache */
    COUNTERS[2].target = 0x1000;
    COUNTERS[2].mode = TM_RESET_TARGET;
    BUSY_WAIT(50000);
    (void)COUNTERS[2].mode;
    (void)COUNTERS[2].mode;

    /* Real measurement */
    COUNTERS[2].mode = TM_RESET_TARGET;
    BUSY_WAIT(50000);

    uint16_t mode1 = COUNTERS[2].mode;
    uint16_t mode2 = COUNTERS[2].mode;

    int flag1 = (mode1 & TM_HIT_TARGET) ? 1 : 0;
    int flag2 = (mode2 & TM_HIT_TARGET) ? 1 : 0;
    /* First read: bit 11 should be set */
    cester_assert_int_eq(1, flag1);
    /* Second read: bit 11 should be cleared */
    cester_assert_int_eq(0, flag2);
)

/* =================================================================
 * Status bits: hit-overflow (bit 12) set on 0xFFFF, cleared on read.
 * ================================================================= */
CESTER_TEST(timerHitOverflowFlagSetAndCleared, timer_tests,
    COUNTERS[2].target = 0xFFFF;
    COUNTERS[2].mode = 0;  /* Free run */
    /* At sysclock ~33MHz, 0xFFFF counts = ~2ms */
    BUSY_WAIT(100000);

    uint16_t mode1 = COUNTERS[2].mode;
    uint16_t mode2 = COUNTERS[2].mode;

    /* First read: bit 12 should be set */
    cester_assert_cmp((int)(mode1 & TM_HIT_OVERFLOW), !=, 0);
    /* Second read: bit 12 should be cleared */
    cester_assert_int_eq(0, (int)(mode2 & TM_HIT_OVERFLOW));
)

/* =================================================================
 * IRQ request flag (bit 10): pulse mode vs toggle mode.
 * Pulse mode (bit7=0): bit 10 stays 1 after IRQ.
 * Toggle mode (bit7=1): bit 10 toggles, may read as 0.
 * ================================================================= */
CESTER_TEST(timerIrqPulseModeBit10, timer_tests,
    COUNTERS[2].target = 0x0080;
    COUNTERS[2].mode = TM_RESET_TARGET | TM_IRQ_TARGET | TM_IRQ_REPEAT;
    BUSY_WAIT(1000);

    uint16_t mode = COUNTERS[2].mode;
    /* Pulse mode: bit 10 should be 1 */
    cester_assert_cmp((int)(mode & TM_IRQ_REQUEST), !=, 0);
)

CESTER_TEST(timerIrqToggleModeBit10, timer_tests,
    /* In toggle mode, bit 10 alternates on each IRQ.
     * Read mode twice with different target counts between reads
     * to verify that bit 10 actually changes state. */
    COUNTERS[2].target = 0x0010;
    COUNTERS[2].mode = TM_RESET_TARGET | TM_IRQ_TARGET | TM_IRQ_REPEAT | TM_IRQ_TOGGLE;
    BUSY_WAIT(200);

    /* Sample bit 10 multiple times to detect toggling */
    int saw_zero = 0;
    int saw_one = 0;
    for (int i = 0; i < 50; i++) {
        /* Re-read mode (which clears status bits but bit 10 reflects toggle state) */
        uint16_t mode = COUNTERS[2].mode;
        if (mode & TM_IRQ_REQUEST) saw_one = 1;
        else saw_zero = 1;
        BUSY_WAIT(10);
    }

    /* In toggle mode, we should see both states */
    cester_assert_int_eq(1, saw_zero);
    cester_assert_int_eq(1, saw_one);
)

/* =================================================================
 * Timer 2 sync modes (bit 0):
 * Modes 0 and 3 = stop counter
 * Modes 1 and 2 = free run
 * ================================================================= */
CESTER_TEST(timerRc2SyncMode0Stop, timer_tests,
    COUNTERS[2].target = 0xFFFF;
    COUNTERS[2].mode = TM_SYNC_EN | TM_SYNC_MODE(0);
    BUSY_WAIT(50000);
    uint16_t v1 = COUNTERS[2].value;
    BUSY_WAIT(50000);
    uint16_t v2 = COUNTERS[2].value;

    cester_assert_int_eq(0, (int)(uint16_t)(v2 - v1));
)

CESTER_TEST(timerRc2SyncMode1Free, timer_tests,
    COUNTERS[2].target = 0xFFFF;
    COUNTERS[2].mode = TM_SYNC_EN | TM_SYNC_MODE(1);
    BUSY_WAIT(50000);
    uint16_t v1 = COUNTERS[2].value;
    BUSY_WAIT(50000);
    uint16_t v2 = COUNTERS[2].value;

    cester_assert_cmp((int)(uint16_t)(v2 - v1), >, 0);
)

CESTER_TEST(timerRc2SyncMode2Free, timer_tests,
    COUNTERS[2].target = 0xFFFF;
    COUNTERS[2].mode = TM_SYNC_EN | TM_SYNC_MODE(2);
    BUSY_WAIT(50000);
    uint16_t v1 = COUNTERS[2].value;
    BUSY_WAIT(50000);
    uint16_t v2 = COUNTERS[2].value;

    cester_assert_cmp((int)(uint16_t)(v2 - v1), >, 0);
)

CESTER_TEST(timerRc2SyncMode3Stop, timer_tests,
    COUNTERS[2].target = 0xFFFF;
    COUNTERS[2].mode = TM_SYNC_EN | TM_SYNC_MODE(3);
    BUSY_WAIT(50000);
    uint16_t v1 = COUNTERS[2].value;
    BUSY_WAIT(50000);
    uint16_t v2 = COUNTERS[2].value;

    cester_assert_int_eq(0, (int)(uint16_t)(v2 - v1));
)

/* =================================================================
 * Counter 0 gate modes (Hblank-synced).
 * Modes 1 and 3 are implemented. Modes 0 and 2 (pause logic) are
 * not yet implemented - use CESTER_MAYBE_TEST to skip on emulator.
 * ================================================================= */

/* Gate mode 0: pause during Hblank.
 * Counter should advance slower than free run. */
CESTER_MAYBE_TEST(timerC0GateMode0PauseDuringHblank, timer_tests,
    COUNTERS[0].target = 0xFFFF;

    /* Measure gated first, then free run, to avoid ordering bias */
    COUNTERS[0].mode = TM_SYNC_EN | TM_SYNC_MODE(0);
    BUSY_WAIT(20000);
    uint16_t gated = COUNTERS[0].value;

    COUNTERS[0].mode = 0;
    BUSY_WAIT(20000);
    uint16_t free_val = COUNTERS[0].value;

    /* Gated value should be less than free run (paused during Hblank) */
    cester_assert_cmp((int)gated, <, (int)free_val);
)

/* Gate mode 1: reset at Hblank.
 * Counter keeps resetting, should show small values. */
CESTER_TEST(timerC0GateMode1ResetAtHblank, timer_tests,
    COUNTERS[0].target = 0xFFFF;
    COUNTERS[0].mode = TM_SYNC_EN | TM_SYNC_MODE(1);
    BUSY_WAIT(50000);
    uint16_t val = COUNTERS[0].value;

    /* Value should be small - resets every scanline (~2130 sysclocks for NTSC) */
    cester_assert_cmp((int)val, <, 0x2000);
)

/* Gate mode 2: reset at Hblank + pause outside.
 * Counter only runs during Hblank and resets each time. */
CESTER_MAYBE_TEST(timerC0GateMode2ResetPauseOutside, timer_tests,
    COUNTERS[0].target = 0xFFFF;
    COUNTERS[0].mode = TM_SYNC_EN | TM_SYNC_MODE(2);
    BUSY_WAIT(50000);
    uint16_t val = COUNTERS[0].value;

    /* Should be small - only counts during Hblank period itself.
     * Hblank is ~200 sysclocks per scanline, so over many scanlines
     * this accumulates but stays much smaller than free run (~45000). */
    cester_assert_cmp((int)val, <, 0x2000);
)

/* Gate mode 3: pause until first Hblank, then free run.
 * After the initial pause, should count at full speed. */
CESTER_TEST(timerC0GateMode3FreeAfterHblank, timer_tests,
    COUNTERS[0].target = 0xFFFF;

    COUNTERS[0].mode = 0;
    BUSY_WAIT(50000);
    uint16_t free_val = COUNTERS[0].value;

    COUNTERS[0].mode = TM_SYNC_EN | TM_SYNC_MODE(3);
    BUSY_WAIT(50000);
    uint16_t gated = COUNTERS[0].value;

    /* After first Hblank, should be close to free run */
    int diff = (int)free_val - (int)gated;
    if (diff < 0) diff = -diff;
    cester_assert_cmp(diff, <, 0x2000);
)

/* =================================================================
 * PE2 scenario: Timer 2, sysclock/8, count to target, IRQ repeat.
 * This is the exact configuration that triggers the PE2 jitter hack
 * in the emulator (JITTER_FLAGS = Rc2OneEighthClock | RcIrqRegenerate | RcCountToTarget).
 * Verify counter value is proportional to elapsed time.
 * ================================================================= */
CESTER_TEST(timerPE2Scenario, timer_tests,
    /* Set up Timer 2 exactly as PE2 does */
    COUNTERS[2].target = 0x1000;
    COUNTERS[2].mode = TM_CLK_DIV8 | TM_IRQ_REPEAT | TM_RESET_TARGET | TM_IRQ_TARGET;

    /* Wait a known amount, then read */
    BUSY_WAIT(50000);
    uint16_t count = COUNTERS[2].value;

    /* Counter should be running and have a reasonable value.
     * At sysclock/8, 5000 loop iterations at ~4 cycles each = ~20000 cycles,
     * divided by 8 = ~2500 counts. Allow wide tolerance since loop timing
     * varies with compiler optimization and cache state. */
    cester_assert_cmp((int)count, >, 100);
    cester_assert_cmp((int)count, <, 0x1000);  /* Should not have wrapped past target */
)

/* =================================================================
 * Dotclock rate measurement.
 * Use Timer1 (hsync) to count 10 scanlines, read Timer0 (dotclock).
 * The ratio gives dots per scanline which depends on GPU hres.
 *
 * Hardware verified on SCPH-5501 NTSC in 512px mode:
 *   680 dots/scanline (expected 682 = 3413/5)
 * ================================================================= */
CESTER_TEST(timerDotclockRate, timer_tests,
    /* Timer1: hsync clock, free run */
    COUNTERS[1].target = 0xFFFF;
    COUNTERS[1].mode = TM_CLK_EXTERNAL;

    /* Timer0: dotclock, free run */
    COUNTERS[0].target = 0xFFFF;
    COUNTERS[0].mode = TM_CLK_EXTERNAL;

    /* Reset both */
    COUNTERS[1].mode = TM_CLK_EXTERNAL;
    COUNTERS[0].mode = TM_CLK_EXTERNAL;

    /* Wait for 10 scanlines */
    while (COUNTERS[1].value < 10) {}

    int dots = COUNTERS[0].value;
    int lines = COUNTERS[1].value;
    int dots_per_line = dots / lines;

    /* Dots per scanline should be reasonable for any resolution:
     * Minimum: 256px mode = 341 dots/line (3413/10)
     * Maximum: 640px mode = 853 dots/line (3413/4)
     * Allow some tolerance for fractional rounding. */
    cester_assert_cmp(dots_per_line, >=, 330);
    cester_assert_cmp(dots_per_line, <=, 860);
)

/* =================================================================
 * Precise dotclock measurements per resolution.
 * Measures dots per N scanlines at each GPU horizontal resolution
 * in both NTSC and PAL modes. Uses 100 scanlines for precision.
 *
 * Hardware verified on SCPH-5501, 2026-04-08:
 *   256px: NTSC 341, PAL 340
 *   320px: NTSC 426, PAL 426 (rounds UP from 425.75)
 *   512px: NTSC 682, PAL 681
 *   640px: NTSC 853, PAL 851
 *   368px: NTSC 487, PAL 486
 * ================================================================= */

CESTER_BODY(
static int measureDotsPerLine(int scanlines) {
    /* Timer1: hsync clock, free run */
    COUNTERS[1].target = 0xFFFF;
    COUNTERS[1].mode = TM_CLK_EXTERNAL;

    /* Timer0: dotclock, free run */
    COUNTERS[0].target = 0xFFFF;
    COUNTERS[0].mode = TM_CLK_EXTERNAL;

    /* Reset both by re-writing mode */
    COUNTERS[1].mode = TM_CLK_EXTERNAL;
    COUNTERS[0].mode = TM_CLK_EXTERNAL;

    /* Wait for exactly N scanlines */
    while (COUNTERS[1].value < scanlines) {}

    int dots = COUNTERS[0].value;
    int lines = COUNTERS[1].value;
    return (dots + lines / 2) / lines;
}
)

/* 256px NTSC: 3413/10 = 341.3 -> 341 */
CESTER_MAYBE_TEST(timerDotclock256NTSC, timer_tests,
    struct DisplayModeConfig cfg = { HR_256, VR_240, VM_NTSC, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 341 - 1); cester_assert_cmp(dpl, <=, 341 + 1);
)

/* 256px PAL: 3406/10 = 340.6 -> 340 */
CESTER_MAYBE_TEST(timerDotclock256PAL, timer_tests,
    struct DisplayModeConfig cfg = { HR_256, VR_240, VM_PAL, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 340 - 1); cester_assert_cmp(dpl, <=, 340 + 1);
)

/* 320px NTSC: 3413/8 = 426.625 -> 426 */
CESTER_MAYBE_TEST(timerDotclock320NTSC, timer_tests,
    struct DisplayModeConfig cfg = { HR_320, VR_240, VM_NTSC, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 426 - 1); cester_assert_cmp(dpl, <=, 426 + 1);
)

/* 320px PAL: 3406/8 = 425.75 -> 426 (only mode that rounds up) */
CESTER_MAYBE_TEST(timerDotclock320PAL, timer_tests,
    struct DisplayModeConfig cfg = { HR_320, VR_240, VM_PAL, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 426 - 1); cester_assert_cmp(dpl, <=, 426 + 1);
)

/* 512px NTSC: 3413/5 = 682.6 -> 682 */
CESTER_MAYBE_TEST(timerDotclock512NTSC, timer_tests,
    struct DisplayModeConfig cfg = { HR_512, VR_240, VM_NTSC, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 682 - 1); cester_assert_cmp(dpl, <=, 682 + 1);
)

/* 512px PAL: 3406/5 = 681.2 -> 681 */
CESTER_MAYBE_TEST(timerDotclock512PAL, timer_tests,
    struct DisplayModeConfig cfg = { HR_512, VR_240, VM_PAL, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 681 - 1); cester_assert_cmp(dpl, <=, 681 + 1);
)

/* 640px NTSC: 3413/4 = 853.25 -> 853 */
CESTER_MAYBE_TEST(timerDotclock640NTSC, timer_tests,
    struct DisplayModeConfig cfg = { HR_640, VR_240, VM_NTSC, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 853 - 1); cester_assert_cmp(dpl, <=, 853 + 1);
)

/* 640px PAL: 3406/4 = 851.5 -> 851 */
CESTER_MAYBE_TEST(timerDotclock640PAL, timer_tests,
    struct DisplayModeConfig cfg = { HR_640, VR_240, VM_PAL, CD_15BITS, VI_OFF, HRE_NORMAL };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 851 - 1); cester_assert_cmp(dpl, <=, 851 + 1);
)

/* 368px NTSC: 3413/7 = 487.57 -> 487 */
CESTER_MAYBE_TEST(timerDotclock368NTSC, timer_tests,
    struct DisplayModeConfig cfg = { HR_256, VR_240, VM_NTSC, CD_15BITS, VI_OFF, HRE_368 };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 487 - 1); cester_assert_cmp(dpl, <=, 487 + 1);
)

/* 368px PAL: 3406/7 = 486.57 -> 486 */
CESTER_MAYBE_TEST(timerDotclock368PAL, timer_tests,
    struct DisplayModeConfig cfg = { HR_256, VR_240, VM_PAL, CD_15BITS, VI_OFF, HRE_368 };
    setDisplayMode(&cfg);
    waitVSync();
    waitVSync();
    measureDotsPerLine(50);
    int dpl = measureDotsPerLine(50);
    cester_assert_cmp(dpl, >=, 486 - 1); cester_assert_cmp(dpl, <=, 486 + 1);
)
