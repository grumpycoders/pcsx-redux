/*
 * VBlank interrupt handler example. Adds a vblank interrupt handler and prints
 * the count of vblanks that occur to the console.
 * 
 * This is basically a port of VBLANK.ASM which has the following copyright:
 *      "copyright 1999 by Doomed/Padua."
 * 
 * Doomed deserves all the credit and more.
 * 
 */
#include <mipsregs.h>

static uint32_t Vblank_handler(void);

static volatile uint32_t vblank_count = 0;
static IntrCB vblank_icb = { 0, NULL, &Vblank_handler };

static uint32_t Vblank_handler(void)
{
    if(!(*R_PS1_I_MASK & IRQ_VBLANK)) return 0;
    if(!(*R_PS1_I_STAT & IRQ_VBLANK)) return 0;

/*
;## If you are using other Vblank stuff as well (cards/pads etc..) you should
;## not acknowledge the vblank, as this handler gets called first.. (que 0,
;## the vsync handler used by the pads etc is in que 2). So define USING_PADS
;## in that case. (Also make sure you init those before this handler.)
*/

#ifdef USING_PADS
    *R_PS1_I_STAT ^= IRQ_VBLANK; // clear VBLANK IRQ pending
#endif

    vblank_count++;

    return 0;
}

int main(void)
{
    uint32_t prev_count = 0;
    printf("\r\nVertical blank example.                        1999\x2C doomed/padua\r\n");

    EnterCriticalSection(); // suspend interrupts
    SysEnqIntrp(0, &Vblank_handler); // add our handler to queue 0(highest priority)
    *R_PS1_I_MASK |= IRQ_VBLANK; // enable the VBLANK IRQ
    ExitCriticalSection(); // resume interrupts

    while(1)
    {
        // wait for vblank_count to change
        while(vblank_count == prev_count);
        // keep track of vblank count
        prev_count = vblank_count;
        printf("VBlank Count: %8x/%d", prev_count, prev_count);
    }

    return 0;
}
