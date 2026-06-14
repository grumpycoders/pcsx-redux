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

/* D-Cache / Scratchpad probe routines for empirical BIU_CONFIG bit-7 testing.
 *
 * Background: salmonoilcapsule (2024-11-14, #1306431366262685716) reported
 * that BIU bit 7 (DS) is the d-cache enable, and bit 3 (RAM) is the actual
 * scratchpad enable. With bit 7 set and bit 3 clear, normal RAM reads cause
 * the d-cache hardware to fill scratchpad SRAM as a side effect, because
 * the scratchpad implementation hardwires the cache tag to the upper bits
 * of the scratchpad address - tag matches never happen from outside the
 * scratchpad range, so every read is a "miss" that writes into scratchpad
 * RAM at (read_addr & 0x3FF).
 *
 * These probes drive the BIU into various combinations of bits 3, 4-5
 * (DBLKSZ), 7 (DS), and the COP0 SwC bit, then perform deterministic read
 * patterns from a known RAM region. The C side checks scratchpad contents
 * after restoring BIU to confirm what got captured and at what granularity.
 *
 * SAFETY: all configuration changes happen with IRQs disabled and from
 * uncached space (KSEG1). BIU is restored to BIU_NORMAL before any printf
 * or other library call that might touch scratchpad. Tests must not leave
 * the BIU in a non-default state across function returns.
 *
 * BIU_CONFIG (0xFFFE0130) bit definitions used here:
 *   Bit 0:    LOCK   - Cache lock mode      (when COP0 SR.IsC=1)
 *   Bit 1:    INV    - Cache invalidation   (when COP0 SR.IsC=1)
 *   Bit 2:    TAG    - Cache tag test mode  (when COP0 SR.IsC=1)
 *   Bit 3:    RAM    - Scratchpad enable
 *   Bit 4-5:  DBLKSZ - D-cache refill size  (per LR33300 docs - empirical here)
 *   Bit 7:    DS     - D-cache enable       (1 + RAM=1: scratchpad; 1 + RAM=0: dcache mode)
 *   Bit 8-9:  IBLKSZ - I-cache refill size  (default 1 = 4-word)
 *   Bit 11:   IS1    - I-cache enable
 *   Bit 13:   RDPRI
 *   Bit 14:   NOPAD
 *   Bit 15:   BGNT
 *   Bit 16:   LDSCH
 *
 * COP0 SR (register 12) bits used:
 *   Bit 16: IsC - Isolate cache
 *   Bit 17: SwC - Swap caches
 */

.set BIU_CONFIG, 0xfffe0130

/* Bus-control bits (RDPRI|NOPAD|BGNT|LDSCH = 0x1e000) must be preserved
   or the bus hangs. IS1 and IBLKSZ_4 keep the i-cache normal during the
   test. RAM and DS are the bits we actually toggle. */
.set BIU_BUS_CTRL,    0x0001e000   /* RDPRI|NOPAD|BGNT|LDSCH                       */
.set BIU_ICACHE_BITS, 0x00000900   /* IS1|IBLKSZ_4                                 */
.set BIU_BASE,        0x0001e900   /* BUS_CTRL | ICACHE_BITS (no RAM, no DS)       */

.set BIU_NORMAL,      0x0001e988   /* RAM|DS|IBLKSZ_4|IS1|RDPRI|NOPAD|BGNT|LDSCH   */

.set SR_ISC,     0x00010000        /* COP0 SR: Isolate Cache              */
.set SR_SWC,     0x00020000        /* COP0 SR: Swap Caches                */
.set SR_ISC_SWC, 0x00030000        /* COP0 SR: Isolate + Swap             */

    .set noreorder

/* =========================================================================
 * dcache_get_biu
 *
 * Read the current BIU_CONFIG value. Trampolines to uncached space so the
 * read goes to the actual register, not some cached shadow.
 *
 * Returns: v0 = BIU_CONFIG
 * ========================================================================= */
    .section .text.dcache_get_biu, "ax", @progbits
    .align 2
    .global dcache_get_biu
    .type dcache_get_biu, @function

dcache_get_biu:
    move  $t5, $ra

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    lui   $t0, %hi(BIU_CONFIG)
    lw    $v0, %lo(BIU_CONFIG)($t0)

    jr    $t5
    nop


/* =========================================================================
 * dcache_set_biu
 *
 * Force BIU_CONFIG to a specific value. Caller is responsible for restoring
 * to BIU_NORMAL before any library call. Runs from uncached space.
 *
 * Arguments:
 *   a0 = BIU value to install
 * ========================================================================= */
    .section .text.dcache_set_biu, "ax", @progbits
    .align 2
    .global dcache_set_biu
    .type dcache_set_biu, @function

dcache_set_biu:
    move  $t5, $ra

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    lui   $t6, %hi(BIU_CONFIG)
    sw    $a0, %lo(BIU_CONFIG)($t6)

    jr    $t5
    nop


/* =========================================================================
 * dcache_run_reads
 *
 * Set BIU to a custom value with IRQs masked, perform `count` consecutive
 * 32-bit loads from `src`, restore BIU to BIU_NORMAL, restore SR, return.
 * The loaded values are discarded (kept only in t1 to defeat dead-code
 * optimization) - the point of this probe is the side effect on scratchpad,
 * not the load result.
 *
 * The reads themselves run from uncached space (this function trampolines).
 * `src` should be a KSEG0 cached address (e.g. 0x80100000) so that the
 * d-cache miss machinery actually fires. Reading from KSEG1 would bypass
 * the d-cache entirely.
 *
 * Arguments:
 *   a0 = BIU value to use during the reads
 *   a1 = source address (KSEG0 cached, word-aligned)
 *   a2 = number of words to read (>= 1)
 *
 * Clobbers: t0-t7, v0
 * ========================================================================= */
    .section .text.dcache_run_reads, "ax", @progbits
    .align 2
    .global dcache_run_reads
    .type dcache_run_reads, @function

dcache_run_reads:
    addiu $sp, $sp, -16
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)

    move  $s0, $a0          /* s0 = test BIU value             */
    move  $s1, $a1          /* s1 = source address             */
    move  $s2, $a2          /* s2 = count                      */

    /* Trampoline to uncached mirror */
    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */

    /* Save COP0 SR, mask IRQs */
    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    /* Install test BIU */
    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    /* Read loop. We deliberately use cached addresses so the (now d-cache-mode
       or no-d-cache) load path fires. */
    move  $t0, $s1
    move  $t2, $s2
2:
    lw    $t1, 0($t0)
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 4

    /* Restore BIU to normal BEFORE the SR restore so any IRQ that fires on
       SR-restore goes through normal scratchpad. */
    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)

    /* Restore SR */
    mtc0  $t7, $12
    nop
    nop

    /* Defeat dead-load elimination: stash last loaded value in v0 */
    move  $v0, $t1

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    jr    $ra
    addiu $sp, $sp, 16


/* =========================================================================
 * dcache_run_reads_strided
 *
 * Same as dcache_run_reads but with an explicit byte stride between loads.
 * Useful for skipping over scratchpad slots and seeing whether neighboring
 * slots get filled (i.e. whether any burst behavior exists at all).
 *
 * Arguments:
 *   a0 = BIU value
 *   a1 = source address
 *   a2 = count
 *   a3 = stride in bytes (must be a multiple of 4)
 * ========================================================================= */
    .section .text.dcache_run_reads_strided, "ax", @progbits
    .align 2
    .global dcache_run_reads_strided
    .type dcache_run_reads_strided, @function

dcache_run_reads_strided:
    addiu $sp, $sp, -20
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)
    sw    $s3, 16($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2
    move  $s3, $a3

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    move  $t0, $s1
    move  $t2, $s2
2:
    lw    $t1, 0($t0)
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addu  $t0, $t0, $s3

    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)

    mtc0  $t7, $12
    nop
    nop

    move  $v0, $t1

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    lw    $s3, 16($sp)
    jr    $ra
    addiu $sp, $sp, 20


/* =========================================================================
 * dcache_run_reads_swc
 *
 * Same as dcache_run_reads but additionally raises COP0 SwC during the
 * reads (without IsC). Speculative path mentioned by salmonoilcapsule
 * to test whether cache-swap mode produces burst-style fills.
 *
 * Arguments:
 *   a0 = BIU value
 *   a1 = source address
 *   a2 = count
 * ========================================================================= */
    .section .text.dcache_run_reads_swc, "ax", @progbits
    .align 2
    .global dcache_run_reads_swc
    .type dcache_run_reads_swc, @function

dcache_run_reads_swc:
    addiu $sp, $sp, -16
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    /* Set SwC (no IsC). Loads now go to / through the i-cache as if it
       were the d-cache. With normal d-cache disabled (RAM=0, DS=1), this
       might or might not interact with scratchpad - we want to see. */
    li    $t0, SR_SWC
    mtc0  $t0, $12
    nop
    nop

    move  $t0, $s1
    move  $t2, $s2
2:
    lw    $t1, 0($t0)
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 4

    /* Drop SwC first */
    mtc0  $0, $12
    nop
    nop

    /* Restore BIU to normal */
    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)

    /* Restore original SR */
    mtc0  $t7, $12
    nop
    nop

    move  $v0, $t1

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    jr    $ra
    addiu $sp, $sp, 16


/* =========================================================================
 * dcache_run_reads_drained
 *
 * Same as dcache_run_reads but inserts `drain_nops` nops between the last
 * load and the BIU restore. Used to test whether the apparent "last fill
 * doesn't land" effect is a pipeline race against BIU restore.
 *
 * Arguments:
 *   a0 = BIU value
 *   a1 = source address
 *   a2 = count (>= 1)
 *   a3 = number of nops to insert before BIU restore (>= 0)
 *
 * The drain loop is `drain_nops` nops executed via a counted branch, NOT
 * unrolled. That keeps the code size reasonable for arbitrary drain counts.
 * ========================================================================= */
    .section .text.dcache_run_reads_drained, "ax", @progbits
    .align 2
    .global dcache_run_reads_drained
    .type dcache_run_reads_drained, @function

dcache_run_reads_drained:
    addiu $sp, $sp, -20
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)
    sw    $s3, 16($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2
    move  $s3, $a3

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    move  $t0, $s1
    move  $t2, $s2
2:
    lw    $t1, 0($t0)
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 4

    /* Pipeline drain: spin a no-op loop. Each iteration is the addiu plus
       the bnez plus the (taken) branch delay slot - about 3 cycles per loop. */
    move  $t2, $s3
    beqz  $t2, 4f
    nop
3:
    addiu $t2, $t2, -1
    bnez  $t2, 3b
    nop
4:

    /* Restore BIU and SR */
    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)
    mtc0  $t7, $12
    nop
    nop

    move  $v0, $t1

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    lw    $s3, 16($sp)
    jr    $ra
    addiu $sp, $sp, 20


/* =========================================================================
 * dcache_run_writes
 *
 * Install custom BIU, perform `count` consecutive 32-bit STORES at `dst`
 * with values (base_pattern XOR index), restore BIU. Tests whether stores
 * also fill scratchpad in d-cache mode (store-side miss-fill behavior).
 *
 * Arguments:
 *   a0 = BIU value
 *   a1 = destination (KSEG0 cached)
 *   a2 = count
 *   a3 = base pattern
 *
 * NOTE: this stores at cached RAM addresses, which will land in main RAM
 * via the store buffer. The interesting question is whether the store
 * value ALSO appears in scratchpad as a side effect.
 * ========================================================================= */
    .section .text.dcache_run_writes, "ax", @progbits
    .align 2
    .global dcache_run_writes
    .type dcache_run_writes, @function

dcache_run_writes:
    addiu $sp, $sp, -20
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)
    sw    $s3, 16($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2
    move  $s3, $a3

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    move  $t0, $s1
    move  $t2, $s2
    li    $t3, 0
2:
    xor   $t1, $s3, $t3
    sw    $t1, 0($t0)
    addiu $t3, $t3, 1
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 4

    /* Drain a few cycles so any in-flight fill lands. */
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)
    mtc0  $t7, $12
    nop
    nop

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    lw    $s3, 16($sp)
    jr    $ra
    addiu $sp, $sp, 20


/* =========================================================================
 * dcache_run_byte_reads
 *
 * Like dcache_run_reads but uses lb instead of lw. Tests whether sub-word
 * loads also fill scratchpad and at what granularity.
 *
 * Arguments: a0 = BIU, a1 = src (byte-aligned), a2 = count
 * ========================================================================= */
    .section .text.dcache_run_byte_reads, "ax", @progbits
    .align 2
    .global dcache_run_byte_reads
    .type dcache_run_byte_reads, @function

dcache_run_byte_reads:
    addiu $sp, $sp, -16
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    move  $t0, $s1
    move  $t2, $s2
2:
    lb    $t1, 0($t0)
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 1

    nop
    nop
    nop
    nop

    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)
    mtc0  $t7, $12
    nop
    nop

    move  $v0, $t1

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    jr    $ra
    addiu $sp, $sp, 16


/* =========================================================================
 * dcache_run_half_reads
 *
 * Like dcache_run_reads but uses lh. Half-word stride.
 *
 * Arguments: a0 = BIU, a1 = src (halfword-aligned), a2 = count
 * ========================================================================= */
    .section .text.dcache_run_half_reads, "ax", @progbits
    .align 2
    .global dcache_run_half_reads
    .type dcache_run_half_reads, @function

dcache_run_half_reads:
    addiu $sp, $sp, -16
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    move  $t0, $s1
    move  $t2, $s2
2:
    lh    $t1, 0($t0)
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 2

    nop
    nop
    nop
    nop

    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)
    mtc0  $t7, $12
    nop
    nop

    move  $v0, $t1

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    jr    $ra
    addiu $sp, $sp, 16


/* =========================================================================
 * dcache_run_writes_at_sp_addr
 *
 * Issue stores to addresses in the SCRATCHPAD ADDRESS RANGE (0x1F800XXX)
 * with custom BIU. Tests whether stores to scratchpad work in DS-only
 * mode (RAM=0). Pattern: words at offsets 0, 4, 8, ..., (count-1)*4 within
 * scratchpad get value (base ^ index).
 *
 * Arguments: a0 = BIU, a1 = sp_byte_offset (0..0x3FC), a2 = count, a3 = base
 * ========================================================================= */
    .section .text.dcache_run_writes_at_sp_addr, "ax", @progbits
    .align 2
    .global dcache_run_writes_at_sp_addr
    .type dcache_run_writes_at_sp_addr, @function

dcache_run_writes_at_sp_addr:
    addiu $sp, $sp, -20
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)
    sw    $s3, 16($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2
    move  $s3, $a3

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    /* dst pointer = 0x1F800000 + sp_byte_offset */
    li    $t0, 0x1f800000
    addu  $t0, $t0, $s1
    move  $t2, $s2
    li    $t3, 0
2:
    xor   $t1, $s3, $t3
    sw    $t1, 0($t0)
    addiu $t3, $t3, 1
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 4

    nop
    nop
    nop
    nop

    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)
    mtc0  $t7, $12
    nop
    nop

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    lw    $s3, 16($sp)
    jr    $ra
    addiu $sp, $sp, 20


/* =========================================================================
 * dcache_run_reads_at_sp_addr
 *
 * Read words from scratchpad address range with custom BIU. Returns the
 * last value loaded (in v0) so the caller can inspect what scratchpad
 * reads return in d-cache-only mode.
 *
 * Arguments: a0 = BIU, a1 = sp_byte_offset (0..0x3FC), a2 = count
 *
 * Returns: v0 = last loaded value
 * ========================================================================= */
    .section .text.dcache_run_reads_at_sp_addr, "ax", @progbits
    .align 2
    .global dcache_run_reads_at_sp_addr
    .type dcache_run_reads_at_sp_addr, @function

dcache_run_reads_at_sp_addr:
    addiu $sp, $sp, -16
    sw    $ra, 0($sp)
    sw    $s0, 4($sp)
    sw    $s1, 8($sp)
    sw    $s2, 12($sp)

    move  $s0, $a0
    move  $s1, $a1
    move  $s2, $a2

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    mfc0  $t7, $12
    mtc0  $0, $12
    nop
    nop

    lui   $t6, %hi(BIU_CONFIG)
    sw    $s0, %lo(BIU_CONFIG)($t6)

    li    $t0, 0x1f800000
    addu  $t0, $t0, $s1
    move  $t2, $s2
2:
    lw    $t1, 0($t0)
    addiu $t2, $t2, -1
    bnez  $t2, 2b
    addiu $t0, $t0, 4

    nop
    nop
    nop
    nop

    li    $t0, BIU_NORMAL
    sw    $t0, %lo(BIU_CONFIG)($t6)
    mtc0  $t7, $12
    nop
    nop

    move  $v0, $t1

    lw    $ra, 0($sp)
    lw    $s0, 4($sp)
    lw    $s1, 8($sp)
    lw    $s2, 12($sp)
    jr    $ra
    addiu $sp, $sp, 16


/* =========================================================================
 * dcache_zero_scratchpad
 *
 * Zero the entire 1KB scratchpad (256 words). Runs from uncached space.
 * BIU must be in BIU_NORMAL on entry (caller's responsibility).
 *
 * No arguments. Clobbers t0-t2.
 * ========================================================================= */
    .section .text.dcache_zero_scratchpad, "ax", @progbits
    .align 2
    .global dcache_zero_scratchpad
    .type dcache_zero_scratchpad, @function

dcache_zero_scratchpad:
    move  $t5, $ra

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    li    $t0, 0x1f800000           /* scratchpad base               */
    li    $t1, 0x1f800400           /* scratchpad end (exclusive)    */
2:
    sw    $0, 0($t0)
    addiu $t0, $t0, 4
    bne   $t0, $t1, 2b
    nop

    jr    $t5
    nop


/* =========================================================================
 * dcache_dump_scratchpad
 *
 * Copy 256 words of scratchpad into the supplied buffer. Runs from
 * uncached space. BIU must be in BIU_NORMAL on entry.
 *
 * Arguments:
 *   a0 = destination buffer (256 words = 1024 bytes)
 *
 * Clobbers t0-t3.
 * ========================================================================= */
    .section .text.dcache_dump_scratchpad, "ax", @progbits
    .align 2
    .global dcache_dump_scratchpad
    .type dcache_dump_scratchpad, @function

dcache_dump_scratchpad:
    move  $t5, $ra

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    li    $t0, 0x1f800000
    li    $t1, 0x1f800400
    move  $t2, $a0
2:
    lw    $t3, 0($t0)
    nop                       /* load delay slot - $t3 is OLD value otherwise */
    sw    $t3, 0($t2)
    addiu $t0, $t0, 4
    bne   $t0, $t1, 2b
    addiu $t2, $t2, 4

    jr    $t5
    nop


/* =========================================================================
 * dcache_fill_pattern
 *
 * Write a deterministic test pattern into a region of cached RAM. Used to
 * pre-stage data that the read probes will then consume. Writes go through
 * the uncached mirror so they are not perturbed by the i-cache (the d-cache
 * doesn't intercept writes - PS1 has no write-allocate).
 *
 * Pattern at word index i: (base_pattern XOR i).
 *
 * Arguments:
 *   a0 = destination address (KSEG0 or KSEG1, will be forced to uncached)
 *   a1 = number of words
 *   a2 = base pattern
 * ========================================================================= */
    .section .text.dcache_fill_pattern, "ax", @progbits
    .align 2
    .global dcache_fill_pattern
    .type dcache_fill_pattern, @function

dcache_fill_pattern:
    move  $t5, $ra

    li    $t0, 0xa0000000
    bal   1f
    nop
1:
    or    $t0, $ra, $t0
    addiu $t0, 4 * 4
    jr    $t0
    nop

    /* --- Uncached --- */
    /* Force destination to uncached mirror */
    li    $t0, 0x1fffffff
    and   $t0, $a0, $t0
    li    $t1, 0xa0000000
    or    $t0, $t0, $t1            /* t0 = uncached(dest) */

    move  $t1, $a1                 /* t1 = count          */
    move  $t2, $a2                 /* t2 = base pattern   */
    li    $t3, 0                   /* t3 = index          */

2:
    xor   $t4, $t2, $t3
    sw    $t4, 0($t0)
    addiu $t3, $t3, 1
    addiu $t0, $t0, 4
    bne   $t3, $t1, 2b
    nop

    jr    $t5
    nop
