/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "common/hardware/cop0.h"
#include "ps1sdk.h"
#include "ps1hwregs.h"
#include "serialio.h"

#include "fileio.h"

static void *_old_putchar = NULL;
static void *_old__putchar = NULL;
static char __last_sio_ch = 0;

typedef struct {
    uint32_t inited, mode, ctrl, baud;
} port_config_t;

static port_config_t sio_config = {0, 0, 0, 0};

void sio_reset(void) { *R_PS1_SIO1_CTRL = SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR; }

void sio_put_byte(uint8_t d) {
    while ((*R_PS1_SIO1_STAT & (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY)) != (SIO_STAT_TX_EMPTY | SIO_STAT_TX_RDY))
        ;
    *R_PS1_SIO1_DATA = d;
    
    if (*R_PS1_SIO1_STAT & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
        // RX Overrun, Frame Error or Parity Error occured

        // I guess this is to preserve the data that's currently in the TX FIFO?
        d = *R_PS1_SIO1_DATA;

        while (*R_PS1_SIO1_STAT & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
            // reset the interrupt and error
            sio_reset();

            delay_ms(5);

            // restore the TX FIFO?
            *R_PS1_SIO1_DATA = d;

            // restore mode and ctrl
            *R_PS1_SIO1_MODE = (sio_config.mode);
            *R_PS1_SIO1_CTRL = (sio_config.ctrl);
        }
    }
    
}

int sio_get_byte(uint32_t timeout)
{
    int ret = -1;

    // this may not be necessary. Some UARTs won't transfer if yout don't though.

    // RTR(Ready To Receive akia "RTS"/Request to Send): on
    *R_PS1_SIO1_CTRL |= SIO_CTRL_RTR_EN;

    // wait for data in the RX FIFO
    if (timeout == 0) {
        while (!(*R_PS1_SIO1_STAT & SIO_STAT_RX_RDY))
        {            
            if (*R_PS1_SIO1_STAT & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
                // RX Overrun, Frame Error or Parity Error occured

                // I guess this is to preserve the data that's currently in the TX FIFO?
                uint8_t d = *R_PS1_SIO1_DATA;

                while (*R_PS1_SIO1_STAT & (SIO_STAT_RX_OVRN_ERR | SIO_STAT_FRAME_ERR | SIO_STAT_PARITY_ERR)) {
                    // reset the interrupt and error
                    sio_reset();

                    delay_ms(5);

                    // restore the TX FIFO?
                    *R_PS1_SIO1_DATA = d;

                    // restore mode and ctrl
                    *R_PS1_SIO1_MODE = (sio_config.mode);
                    *R_PS1_SIO1_CTRL = (sio_config.ctrl | SIO_CTRL_RTR_EN);
                }
            }
        }
            ;
    } else {
        uint32_t tries = 0;
        while (!(*R_PS1_SIO1_STAT & SIO_STAT_RX_RDY)) {
            if (++tries >= timeout) goto _done;
        }
    }

    // pop a byte from the RX FIFO
    ret = *R_PS1_SIO1_DATA;

_done:
    // RTR/RTS: off
    *R_PS1_SIO1_CTRL &= ~(SIO_CTRL_RTR_EN);

    return ret;
}

static int force_dos_line_endings = 1;

int sio_putchar(char ch)
{
	if(ch == 0x0A)
	{
        if(force_dos_line_endings)
            if(__last_sio_ch != 0x0D) sio_put_byte(0x0D);
	}
	
	sio_put_byte(ch);
	__last_sio_ch = ch;
    return 0;
}

void sio_puts(const char *s)
{
	while(*s != '\0') sio_putchar(*(s++));
}

void sio_print8(uint8_t d)
{
	const char hex_chars[] = "0123456789ABCDEF";
	sio_putchar(hex_chars[(d >> 4) & 0x0F]);
	sio_putchar(hex_chars[d & 0x0F]);
}

void sio_print16(uint16_t d)
{
	sio_print8((d >>  8) & 0xFF);
	sio_print8((d >>  0) & 0xFF);
}

void sio_print32(uint32_t d)
{
	sio_print8((d >> 24) & 0xFF);
	sio_print8((d >> 16) & 0xFF);
	sio_print8((d >>  8) & 0xFF);
	sio_print8((d >>  0) & 0xFF);
}

int sio_hook_putchar(void)
{
	uint32_t *table = GetB0Table();
	
	_old_putchar = (void *) ((uint32_t *) 0x200)[60];
	((uint32_t *) 0x200)[60] = (uint32_t) &sio_putchar; // hook 0xA0 call 60(putchar)

	_old__putchar = (void *) table[61];
	table[61] = (uint32_t) &sio_putchar; // hook 0xB0 call 61(_putchar)

	FlushCache();
	return 0;
}

int sio_unhook_putchar(void)
{
	uint32_t *table = GetB0Table();
	
	if(_old_putchar != NULL) 
		((uint32_t *) 0x200)[60] = (uint32_t) _old_putchar; // restore 0xA0 call 60(putchar)
	if(_old__putchar != NULL) 
		((uint32_t *) table)[61] = (uint32_t) _old__putchar; // restore 0xB0 call 61(_putchar)
}

//~ int sio_init_tty(int baud)
//~ {
	//~ sio_init(1, baud);
	//~ sio_hook_putchar();
//~ }

void init_sio(uint32_t baud)
{
    /* initialize SIO1 with RX and TX FIFOs enabled */
    *R_PS1_SIO1_CTRL = (SIO_CTRL_RX_EN | SIO_CTRL_TX_EN);
    /* 8bit, no-parity, 1 stop-bit */
    *R_PS1_SIO1_MODE = (SIO_MODE_CHLEN_8 | SIO_MODE_P_NONE | SIO_MODE_SB_1 | SIO_MODE_BR_16);
    *R_PS1_SIO1_BAUD = (2073600/baud);
}

int DelSIO(void) {
    close(stdin);
    close(stdout);
    DelDevice("tty");

    sio_reset();

    AddDummyConsoleDevice();

    if (open("tty00:", O_RDONLY) != stdin) return 1;
    if (open("tty00:", O_WRONLY) != stdout) return 1;

    return 0;
}

int main(void)
{
    DelSIO();
    init_sio(115200);
    
  
    // b0rked.  Used to work, wtf did I fuck up?
//    sio_hook_putchar();

    sio_puts("Hello, pixel. Would you like to play a game?\n");
    sio_puts("No, this isn't a saw reference.  Fuck them!\n");
    sio_puts("I'mma do it! Hold my beer!\n");
    

//    printf("I'mma do it!\n");

    uint32_t d = *(uint32_t *) 0x1F801008;
    d = (((d >> 16) + 4) << 16) | (d & 0xFFFF);
    *(uint32_t *) 0x1F801008 = d;

//    printf("Done did it.\n");
    for(int addr = 0x1F000000; addr < 0x1F800000; addr += 0x00020000)
    {
        sio_print32(addr);
        sio_puts(": 0x");
        sio_print32(*(uint32_t *) addr);
//        sio_puts((const char *) (addr + 4));
        sio_puts("\n");
    }
   
    return 0;
}
