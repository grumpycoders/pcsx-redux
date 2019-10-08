/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either verttyn 2 of the License, or     *
 *   (at your option) any later verttyn.                                   *
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
#include "tty.h"

#include "fileio.h"

static void *_old_putchar = NULL;
static void *_old__putchar = NULL;
static char __last_tty_ch = 0;

static void sio_reset(void) { *R_PS1_SIO1_CTRL = SIO_CTRL_RESET_INT | SIO_CTRL_RESET_ERR; }

static int force_dos_line_endings = 1;

int tty_putchar(char ch)
{
	if(ch == 0x0A)
	{
        if(force_dos_line_endings)
            if(__last_tty_ch != 0x0D) tty_put_byte(0x0D);
	}
	
	tty_put_byte(ch);
	__last_tty_ch = ch;
    return 0;
}

void tty_puts(const char *s)
{
	while(*s != '\0') tty_putchar(*(s++));
}

void tty_print8(uint8_t d)
{
	const char hex_chars[] = "0123456789ABCDEF";
	tty_putchar(hex_chars[(d >> 4) & 0x0F]);
	tty_putchar(hex_chars[d & 0x0F]);
}

void tty_print16(uint16_t d)
{
	tty_print8((d >>  8) & 0xFF);
	tty_print8((d >>  0) & 0xFF);
}

void tty_print32(uint32_t d)
{
	tty_print8((d >> 24) & 0xFF);
	tty_print8((d >> 16) & 0xFF);
	tty_print8((d >>  8) & 0xFF);
	tty_print8((d >>  0) & 0xFF);
}

int tty_hook_putchar(void)
{
	uint32_t *table = GetB0Table();
	
	_old_putchar = (void *) ((uint32_t *) 0x200)[60];
	((uint32_t *) 0x200)[60] = (uint32_t) &tty_putchar; // hook 0xA0 call 60(putchar)

	_old__putchar = (void *) table[61];
	table[61] = (uint32_t) &tty_putchar; // hook 0xB0 call 61(_putchar)

	FlushCache();
	return 0;
}

int tty_unhook_putchar(void)
{
	uint32_t *table = GetB0Table();
	
	if(_old_putchar != NULL) 
		((uint32_t *) 0x200)[60] = (uint32_t) _old_putchar; // restore 0xA0 call 60(putchar)
	if(_old__putchar != NULL) 
		((uint32_t *) table)[61] = (uint32_t) _old__putchar; // restore 0xB0 call 61(_putchar)
}

//~ int tty_init_tty(int baud)
//~ {
	//~ tty_init(1, baud);
	//~ tty_hook_putchar();
//~ }

int DelTTY(void) {
    close(stdin);
    close(stdout);
    DelDevice("tty");

    sio_reset();

    AddDummyConsoleDevice();

    if (open("tty00:", O_RDONLY) != stdin) return 1;
    if (open("tty00:", O_WRONLY) != stdout) return 1;

    return 0;
}

int init_tty(void)
{
    DelTTY();
   
    return 0;
}
