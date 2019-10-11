/*
 * 
 * PS1 Action Replay/GameShark v1 and v2 communications library.
 * 
 */
#include <ps1sdk.h>

uint8_t AR12_exchange8(uint8_t d)
{
	uint8_t rv;
	while((*AR12_STATUS & 0x01) == 0);
	rv = *AR12_RXD;
	*AR12_TXD = d;
	return rv;
}

uint16_t AR12_exchange16(uint16_t d)
{
	uint16_t rv;
	rv = ((AR12_exchange8((d >> 8) & 0xFF) << 8) |
		(AR12_exchange8(d & 0xFF) <<  0));
	return rv;
}

uint32_t AR12_exchange32(uint32_t d)
{
	uint32_t rv;
	rv = ((AR12_exchange16((d >> 16) & 0xFFFF) << 16) |
		(AR12_exchange16(d & 0xFFFF) <<  0));
	return rv;
}

uint8_t AR12_read8(void)
{
	uint8_t rv;
	while((*AR12_STATUS & 0x01) == 0);
	rv = *AR12_RXD;
	*AR12_TXD = rv;
	return rv;
}

uint16_t AR12_read16(void)
{
	uint16_t rv;
	rv = ((AR12_read8() << 8) |
		(AR12_read8() <<  0));
	return rv;
}

uint32_t AR12_read32(void)
{
	uint32_t rv;
	rv = ((AR12_read16() << 16) |
		(AR12_read16() <<  0));
	return rv;
}

void processComms(void)
{
	int i;
	uint8_t cmd;
	
	if(*AR12_RXD != 'W') return;
	
	while(AR12_exchange8('R') != 'W');
	while(AR12_exchange8('W') != 'B');
	cmd = AR12_read8();	
	switch(cmd)
	{
		case 'U': // Upload
		case 'X': // eXecute
		{
			addr = AR12_read32();
			len = AR12_read32();
			for(i = 0; i < len; i++)
			{
				d = AR12_read8();
				((uint8_t *) (addr))[i] = d;
				csum += d;
			}
			
			if(AR12_read16() != (csum & 0xFFFF))
			{
				AR12_exchange16(0x4243); // "BC"
				break;
			}
			
			old_sr = GetC0_SR();
			SetC0_SR(old_sr & 0xFFFFFFFC); // disable interrupts and put kernel in user mode?
			
			AR12_exchange16(0x4F4B); // "OK"
			if(cmd == 'X')
			{
				(*((void(**)()) addr))();
				AR12_exchange16(0x4F4B); // "BF"
			}
			
			SetC0_SR(old_sr);
			
			break;
		}
		default:
		{
			AR12_exchange16(0x4258); // "BX"
			break;
		}
	}
}
