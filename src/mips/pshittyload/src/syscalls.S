.set push
.set noreorder
.set noat

#include <mipsregs.h>

.text

.macro M_KCALL, label, tablenum, callnum
.global \label
.type \label, @function
.ent \label
\label:
                li      t2, \tablenum
                jr      t2
                li      t1, \callnum
.end \label
.endm

.macro M_SYSCALL, label, callNum
.global \label
.type \label, @function
.ent \label
\label:
                li      a0, \callNum
                syscall
                jr      ra
                nop
.end \label
.endm

/* this will only be accurate if interrupts are disabled */
.global delay_ms
.type delay_ms, @function
.ent delay_ms
delay_ms:
                li      t0, 1665
_delay_ms_l2:
                bnez    t0, _delay_ms_l2
                addiu   t0, -1
                bnez    a0, delay_ms
                addiu   a0, -1
                jr      ra
                nop
.end delay_ms

M_KCALL printf, 0xA0, 0x003F
M_KCALL FlushCache, 0xA0, 0x0044

M_SYSCALL   EnterCriticalSection, 1
M_SYSCALL   ExitCriticalSection, 2

.set pop
