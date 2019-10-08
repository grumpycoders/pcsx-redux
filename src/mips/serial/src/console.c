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

// sizeof() == 0x50(80)
static DeviceDriver tty_dd =
{
    name: "tty",                            // 0x00 - unique device name
    type: DEV_TYPE_CHAR | DEV_TYPE_TTY,     // 0x04 - TTY character device.
    block_size: 1,                          // 0x08 - 1 byte per block
    desc: "TTY Console",                    // 0x0C - description of device
    init: _tty_init, // 0x10 - pointer to "init" function. Called by AddDevice()
    open: _tty_open, // 0x14 - pointer to "open" function.
    strategy: _tty_strategy, // 0x18 - pointer to "strategy" function.
    close: _tty_close, // 0x1C - pointer to "close" function.
    ioctl: _tty_ioctl, // 0x20 - pointer to "ioctl" function.
    read: _tty_read, // 0x24 - pointer to "read" function.
    write: _tty_write, // 0x28 - pointer to "write" function.
    delete: _tty_delete, // 0x2C - pointer to "delete" function.
    undelete: _tty_undelete, // 0x30 - pointer to "undelete" function.
    firstfile: _tty_firstfile, // 0x34 - pointer to "firstfile" function.
    nextfile: _tty_nextfile, // 0x38 - pointer to "nextfile" function.
    format: _tty_format, // 0x3C - pointer to "format" function.
    chdir: _tty_chdir, // 0x40 - pointer to "cd" function.
    rename: _tty_rename, // 0x44 - pointer to "rename" function.
    deinit: _tty_deinit, // 0x48 - pointer to "deinit" function.  Called by RemDevice()
    lseek: _tty_lseek, // 0x4C - pointer to "lseek" function.    
};

int init_tty(void)
{
    DelTTY();
   
    return 0;
}
