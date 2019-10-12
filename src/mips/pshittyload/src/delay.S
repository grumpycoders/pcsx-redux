.set push
.set noreorder
.set noat

#include <mipsregs.h>

.text

.global shortWait
.type shortWait, @function
.ent shortWait
shortWait:
_shortWait_l1:
                bnez    a0, _shortWait_l1
                addiu   a0, a0, -1
                jr      ra
                nop
.end shortWait

/* this will only be accurate if interrupts are disabled */

/* aka "longWait()" */
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

.set pop
