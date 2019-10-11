/*
 * PS1 IRQs and such
 */

#ifndef _PS1INTERRUPTS_H
#define _PS1INTERRUPTS_H

#ifdef __cplusplus
extern "C" {
#endif


/* PS1 IRQs */

// V-Blank(external)
#define PS1_IRQ_VB (0)
// GPU(external)
#define PS1_IRQ_GPU (1)
// CD-ROM Controller(external)
#define PS1_IRQ_CD (2)
// DMA Controller(internal)
#define PS1_IRQ_DMAC (3)
// Root-Counter 0(internal)
#define PS1_IRQ_RC0 (4)
// Root-Counter 1(internal)
#define PS1_IRQ_RC1 (5)
// Root-Counter 2(internal)
#define PS1_IRQ_RC2 (6)

// SIO0, pads/card(internal)
#define PS1_IRQ_SIO0 (7)

// SIO1, serial port(internal)
#define PS1_IRQ_SIO1 (8)

// SPU(external)
#define PS1_IRQ_SPU (9)

// EXP1(external)
// NOTE: IRQ 10 is shared by Expansion 1 and the game pads
//      but is likely only used for lightgun stuff.
#define PS1_IRQ_EXP1 (10)
// SIO1(internal) - VERIFY THIS!
//#define PS1_IRQ_SIO1    (11)

#ifdef __cplusplus
}
#endif

#endif /* _PS1INTERRUPTS_H */
