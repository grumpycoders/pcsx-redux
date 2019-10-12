.set push
.set noreorder
.set noat
/*
    #define XP_STAT ((volatile uint8_t *) 0x1F060000)
    #define XP_CTRL ((volatile uint8_t *) 0x1F060001)
    #define XP_STAT ((volatile uint8_t *) 0x1F060002)


uint8_t AR12_exch8(uint8_t d)
{
    uint8_t rv;
    
    // 0x1F020010
    while((*AR12_STAT & 1) == 0);
    // 0x1F060000
    rv = *AR12_DATA;
    *AR12_DATA = d;
    return rv;
}

uint8_t XP_read8(void)
{
    uint8_t d;
    while((*XP_STAT & 1) == 0);

    d = *XP_CTRL;
    *XP_CTRL = 0x08;

    while((*XP_STAT & 1) != 0);
    *XP_CTRL = 0;
    return d;
}

uint8_t COMMS_read8(void)
{
    if(!isXP)
    {
        return AR12_Exchange8(0);
    }
}
*/
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


void shortWait(uint32_t n);
void longWait(uint32_t n);


.global longWait
.type longWait, @function
.ent longWait
longWait:
_longWait_l1:
                li      t0, 1665
_longWait_l2:
                bnez    t0, _longWait_l2
                addiu   t0, -1                
                bnez    a0, _longWait_l1
                addiu   a0, -1
                jr      ra
                nop
.end longWait


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
