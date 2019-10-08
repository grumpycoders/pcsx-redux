/* COP0 Registers */

#ifndef _COP0REGS_H
#define _COP0REGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* BreakPoint Control */
#define C0_BPC $3
/* BreakPoint on Data Access */
#define C0_BDA $5
/* BreakPoint on Data Access */
#define C0_DCIC $7
/* Bad Virtual Address */
#define C0_BADVADDR $8
// Breakpoint Data Access Mask
#define C0_BDAM $9
// Breakpoint Program Counter Mask
#define C0_BPCM $11

/* Status Register */
#define C0_STATUS $12

/* Cause Register */
#define C0_CAUSE $13

/* Error PC Register */
#define C0_EPC $14

/* Processor ID */
#define C0_PRID $15

// Interrupt Enable(current)
#define C0_SR_IEC (1 << 0)
// Kernel/User mode(current)
#define C0_SR_KUC (1 << 1)
// Interrupt Enable(previous)
#define C0_SR_IEP (1 << 2)
// Kernel/User mode(previous)
#define C0_SR_KUP (1 << 3)
// Interrupt Enable(old)
#define C0_SR_IEO (1 << 4)
// Kernel/User mode(old)
#define C0_SR_KUO (1 << 5)

/* Interrupt Mask 0 */
#define C0_SR_IMO (1 << 8)
/* Interrupt Mask 1 */
#define C0_SR_IM1 (1 << 9)
/* Interrupt Mask 2 */
#define C0_SR_IM2 (1 << 10)
/* Interrupt Mask 3 */
#define C0_SR_IM3 (1 << 11)
/* Interrupt Mask 4 */
#define C0_SR_IM4 (1 << 12)
/* Interrupt Mask 5 */
#define C0_SR_IM5 (1 << 13)
/* Interrupt Mask 6 */
#define C0_SR_IM6 (1 << 14)
/* Interrupt Mask 7 */
#define C0_SR_IM7 (1 << 15)

/* Isolate Cache */
#define C0_SR_ISC (1 << 16)
/* Swap Caches */
#define C0_SR_SWC (1 << 17)
/* Parity Zero */
#define C0_SR_PZ (1 << 18)
/* Cache Miss */
#define C0_SR_CM (1 << 19)
/* Parity Error */
#define C0_SR_PE (1 << 20)
/* TLB Shutdown */
#define C0_SR_TS (1 << 21)
/* Boot-time Exception Vector */
#define C0_SR_BEV (1 << 22)

/* Reverse Endian enable */
#define C0_SR_RE (1 << 25)

/* Coprocessor 0 Usable */
#define C0_SR_CU0 (1 << 28)
/* Coprocessor 1 Usable */
#define C0_SR_CU1 (1 << 29)
/* Coprocessor 2 Usable */
#define C0_SR_CU2 (1 << 30)
/* Coprocessor 3 Usable */
#define C0_SR_CU3 (1 << 31)

// R3000A COP0 DCIC register bits

/* These are R/W, used to enable/disable various debug/cache things */
#define C0_DCIC_TR      (1 << 31)  /* Trap enable */
#define C0_DCIC_UD      (1 << 30)  /* User debug enable */
#define C0_DCIC_KD      (1 << 29)  /* Kernel debug enable */
#define C0_DCIC_TE      (1 << 28)  /* Trace enable */
#define C0_DCIC_DW      (1 << 27)  /* Enable data access breakpoints on write */
#define C0_DCIC_DR      (1 << 26)  /* Enable data access breakpoints on read */
#define C0_DCIC_DAE     (1 << 25)  /* Enable data addresss breakpoints(Is this valid?) */
#define C0_DCIC_PCE     (1 << 24)  /* Enable instruction breakpoints */
#define C0_DCIC_DE      (1 << 23)  /* Debug Enable */
#define C0_DCIC_DL      (1 << 15)  /* Data cache line invalidate */
#define C0_DCIC_IL      (1 << 14)  /* Instruction cache line invalidate */
#define C0_DCIC_D       (1 << 13)  /* Data cache invalidate enable */
#define C0_DCIC_I       (1 << 12)  /* Instr. cache invalidate enable */
/* The rest of these are R/O, set by the CPU to indicate the type of debug exception that occured */
#define C0_DCIC_T       (1 <<  5)  /* Trace */
#define C0_DCIC_W       (1 <<  4)  /* Write reference */
#define C0_DCIC_R       (1 <<  3)  /* Read reference */
#define C0_DCIC_DA      (1 <<  2)  /* Data address */
#define C0_DCIC_PC      (1 <<  1)  /* Program counter */
#define C0_DCIC_DB      (1 <<  0)  /* Debug */

#ifdef __cplusplus
}
#endif

#endif /* _COP0REGS_H */
