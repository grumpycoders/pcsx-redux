#ifndef _MIPSREGS_H
#define _MIPSREGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* general registers */

#define r0 $0
#define r1 $1
#define r2 $2
#define r3 $3
#define r4 $4
#define r5 $5
#define r6 $6
#define r7 $7
#define r8 $8
#define r9 $9
#define r10 $10
#define r11 $11
#define r12 $12
#define r13 $13
#define r14 $14
#define r15 $15
#define r16 $16
#define r17 $17
#define r18 $18
#define r19 $19
#define r20 $20
#define r21 $21
#define r22 $22
#define r23 $23
#define r24 $24
#define r25 $25
#define r26 $26
#define r27 $27
#define r28 $28
#define r29 $29
#define r30 $30
#define r31 $31

#define zero $0
//#define at      $1
#define v0 $2
#define v1 $3
#define a0 $4
#define a1 $5
#define a2 $6
#define a3 $7
#define t0 $8
#define t1 $9
#define t2 $10
#define t3 $11
#define t4 $12
#define t5 $13
#define t6 $14
#define t7 $15
#define s0 $16
#define s1 $17
#define s2 $18
#define s3 $19
#define s4 $20
#define s5 $21
#define s6 $22
#define s7 $23
#define t8 $24
#define t9 $25
#define k0 $26
#define k1 $27
#define gp $28
#define sp $29
#define s8 $30
#define fp $30
#define ra $31

/* COP0 Registers */

#define C0_INX $0
#define C0_RAND $1
#define C0_TLBLO $2
#define C0_BPC $3
#define C0_CTXT $4
#define C0_BDA $5
#define C0_PIDMASK $6
#define C0_DCIC $7
/* Bad Virtual Address */
#define C0_BADVA $8
#define C0_BDAM $9
#define C0_TLBHI $10
#define C0_BPCM $11

/* Status Register */
#define C0_STATUS $12

/* Cause Register */
#define C0_CAUSE $13

/* Error PC Register */
#define C0_EPC $14

/* Processor ID */
#define C0_PRID $15

/* EEREG?? */
#define C0_EEREG $16

// Interrupt Enable(current)
#define SR_IEC (1 << 0)
// Kernel/User mode(current)
#define SR_KUC (1 << 1)
// Interrupt Enable(previous)
#define SR_IEP (1 << 2)
// Kernel/User mode(previous)
#define SR_KUP (1 << 3)
// Interrupt Enable(old)
#define SR_IEO (1 << 4)
// Kernel/User mode(old)
#define SR_KUO (1 << 5)

/* Interrupt Mask 0 */
#define SR_IMO (1 << 8)
/* Interrupt Mask 1 */
#define SR_IM1 (1 << 9)
/* Interrupt Mask 2 */
#define SR_IM2 (1 << 10)
/* Interrupt Mask 3 */
#define SR_IM3 (1 << 11)
/* Interrupt Mask 4 */
#define SR_IM4 (1 << 12)
/* Interrupt Mask 5 */
#define SR_IM5 (1 << 13)
/* Interrupt Mask 6 */
#define SR_IM6 (1 << 14)
/* Interrupt Mask 7 */
#define SR_IM7 (1 << 15)

/* Isolate Cache */
#define SR_ISC (1 << 16)
/* Swap Caches */
#define SR_SWC (1 << 17)
/* Parity Zero */
#define SR_PZ (1 << 18)
/* Cache Miss */
#define SR_CM (1 << 19)
/* Parity Error */
#define SR_PE (1 << 20)
/* TLB Shutdown */
#define SR_TS (1 << 21)
/* Boot-time Exception Vector */
#define SR_BEV (1 << 22)

/* Reverse Endian enable */
#define SR_RE (1 << 25)

/* Coprocessor 0 Usable */
#define SR_CU0 (1 << 28)
/* Coprocessor 1 Usable */
#define SR_CU1 (1 << 29)
/* Coprocessor 2 Usable */
#define SR_CU2 (1 << 30)
/* Coprocessor 3 Usable */
#define SR_CU3 (1 << 31)

#ifdef __cplusplus
}
#endif

#endif /* _MIPSREGS_H */
