#include "flash.h"


// TODO: time these to see how long the wait really is.
__attribute__((noinline)) void shortWait(int n)
{
	int i = 6499;
	while((i -= 25) >= 0);
}

// TODO: time these to see how long the wait really is.
__attribute__((noinline)) void longWait(void)
{
	int i = 0;
	for(i = 0; i < 350; i += 14)
	{
		shortWait(); shortWait(); shortWait(); shortWait();
		shortWait(); shortWait(); shortWait(); shortWait();
		shortWait(); shortWait(); shortWait(); shortWait();
		shortWait(); shortWait();
	}
}

// performs a 3-byte "unlock cycle"
#define M_FlashUnlockCycle(__base, __cmd) \
{ \
    ((volatile uint8_t *) __base)[0xAAA] = 0xAA; \
    ((volatile uint8_t *) __base)[0x555] = 0x55; \
    ((volatile uint8_t *) __base)[0xAAA] = (__cmd); \
}

void FlashUnlockCycle(void *base, uint8_t cmd) { M_FlashUnlockCycle(base, cmd); }

// reset the device state
void Flash_Reset(void *base) { ((volatile uint8_t *) base)[0x555] = 0xF0; }

// enters "Autoselect" mode which allows access to chip information
// by reading from addresses 0+
// Muse be exited with a Reset(see Flash_Reset)
void Flash_Autoselect(void *base) { M_FlashUnlockCycle(base, 0x90); }

void Flash_ChipErase(void *base)
{
    M_FlashUnlockCycle(base, 0x80); // Unlock Cycle 1
    M_FlashUnlockCycle(base, 0x10); // Unlock Cycle 2

    // wait for operation to complete.
    while(isBitToggling(base));
}

// erases a sector
void Flash_SectorErase(void *base, uint32_t offset)
{
    M_FlashUnlockCycle(base, 0x80); // Unlock Cycle 1
    
    ((volatile uint8_t *) base)[0xAAA] = 0xAA; // Unlock Cycle 2
    ((volatile uint8_t *) base)[0x555] = 0x55;
    ((volatile uint8_t *) base)[offset] = 0x30;

    // wait for operation to complete.
    while(isBitToggling(base + offset));
}

// programs "size" number of data from "src" to flash starting at (base + offs)
// NOTE: Flash_ProgramFast() is a better option.
void Flash_Program(void *base, uint32_t offs, void *src, uint32_t size)
{
    int i;
    
    volatile uint8_t *b = (volatile uint8_t *) base;
    volatile uint8_t *d = (volatile uint8_t *) base + offs;
    volatile uint8_t *s = (volatile uint8_t *) src;
    
    for(i = 0; i < size; i++)
    {
        M_FlashUnlockCycle(b, 0xA0); // Unlock Cycle 1(3 cycles)
        d[i] = s[i];
        // I don't *think* you have to wait for bit toggling to cease here...
    }
    
    // wait for operation to complete.
    while(isBitToggling(base));
}

// programs "size" number of data from "src" to flash starting at (base + offs).
// NOTE: uses the "Unlock Bypass" mode along with the "Unlock Bypass Program"
//  command instead of the normal "Program" command.  This reduces programming by
//  about half the cycles.
void Flash_ProgramFast(void *base, uint32_t offs, void *src, uint32_t size)
{
    int i;

    volatile uint8_t *b = (volatile uint8_t *) base;
    volatile uint8_t *d = (volatile uint8_t *) base + offs;
    volatile uint8_t *s = (volatile uint8_t *) src;
    
    M_FlashUnlockCycle(base, 0x20); // "Unlock Bypass"

    for(i = 0; i < size; i++)
    {
        b[0xAAA] = 0xA0;    // Unlock Bypass Program
        d[i] = s[i];        // program 1 byte
        // I don't *think* you have to wait for bit toggling to cease here...
    }

    b[0] = 0x90;    // Unlock Bypass Reset(2 cycles)
    b[0] = 0x00;
    
    // wait for operation to complete.
    while(isBitToggling(base));
}

// try to detect flash memory device at "base".
// args:
//  base: base address pointer of device.
//  p_mid: pointer where a uint16_t containing the manufacturer ID can be written.
//      Can be NULL.
//  p_did: pointer where a uint16_t containing the device ID can be written.
//      Can be NULL.
// returns:
//  lower 16: manufacturer ID
//  upper 16: device ID
//
// NOTE: No attempt is made to validate these IDs! They may be completely bogus if there's no device or it doesn't support
//  this method of reading the IDs.
//
uint32_t flash_detect(void *base, uint16_t *p_mid, uint16_t *p_did)
{
	uint16_t man_id, dev_id;
	uint8_t *p = (uint8_t *) base;
    
    Flash_Autoselect(base); // enter Autoselect mode
	longWait();
	
	man_id = p[0x000];  // byte 0 is the manufacturer ID
	dev_id = p[0x001];  // byte 1 is the device ID
                        // CFI stuff next but we don't need it

	longWait();
    
    Flash_Reset(base); // reset the device to exit Autoselect mode
    
    if(p_mid) *p_mid = man_id;
    if(p_did) *p_did = dev_id;
    return (man_id | (dev_id << 16));
}
