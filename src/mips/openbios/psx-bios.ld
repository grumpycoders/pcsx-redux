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

OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_ARCH(mips)

EXTERN(_reset)
ENTRY(_reset)

MEMORY {
    kseg0i(rwx): ORIGIN = 0x00000000, LENGTH = 0x500
    kseg0 (rwx): ORIGIN = 0x00000500, LENGTH = 2M - 0x500
    ram (rwx)  : ORIGIN = 0x80010000, LENGTH = 2M - 0x10000
    rom (rx)   : ORIGIN = 0xbfc00000, LENGTH = 512K
    dcache     : ORIGIN = 0x1f800000, LENGTH = 0x400
}

STACK_SIZE      = 0x10000;

__ram_top       = ORIGIN(ram) + LENGTH(ram);
__sp            = __ram_top - 0x100;

__dcache        = ORIGIN(dcache);
__dcache_top    = ORIGIN(dcache) + LENGTH(dcache);

__data_len_val  = (__data_end - __data_start);
__bss_len_val   = (__bss_end - __bss_start);

__stack_start   = ORIGIN(ram) + LENGTH(ram) - STACK_SIZE;

SECTIONS {
    .base (NOLOAD) : {
        __vector_00 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_40 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        __globals60 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_80 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_a0 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_b0 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_c0 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_d0 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_e0 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        __vector_f0 = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        __globals = .;
        . = ALIGN(0x200);
        __ramA0table = .;
        . = ALIGN(0x500);
    } > kseg0i

    __text_start = .;
    .text : {
        *(.boot)

        *(.init)
        . = ALIGN(4);
        __preinit_array_start = .;
        KEEP (*(SORT(.preinit_array.*)))
        KEEP (*(.preinit_array))
        . = ALIGN(4);
        __preinit_array_end = .;
        __init_array_start = .;
        KEEP (*(SORT(.init_array.*)))
        KEEP (*(.init_array))
        KEEP (*(.ctors))
        . = ALIGN(4);
        __init_array_end = .;

        KEEP (*(SORT_NONE(.fini)))
        . = ALIGN(4);
        __fini_array_start = .;
        KEEP (*(.fini_array))
        KEEP (*(SORT(.fini_array.*)))
        KEEP (*(.dtors))
        . = ALIGN(4);
        __fini_array_end = .;

        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(.text .stub .text.* .gnu.linkonce.t.*)
        . = ALIGN(4);
    } > rom

    . = ALIGN(4);
    __text_end = .;

    .rodata : {
        g_defaultConfiguration = .;
        LONG(4);
        LONG(10);
        LONG(__sp);
        __data_len = .;
        LONG(__data_len_val);
        __bss_len = .;
        LONG(__bss_len_val);
        . = ALIGN(32);
        *(.rodata .rodata.* .rdata .rdata.* .gnu.linkonce.r.* .rodata1)
    } > rom

    .rom_data_start : {
        __rom_data_start = .;
    } > rom

    .data : {
        __data_start = .;
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        LONG(0); LONG(0); LONG(0); LONG(0);
        *(.ramtext)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.data1)
        *(.got.plt)
        *(.got)
        . = ALIGN(32);
        __data_end = .;
    } > kseg0 AT > rom

    .sbss (NOLOAD) : {
        . = ALIGN(32);
        __bss_start = .;
        *(.dynsbss)
        *(.sbss .sbss.* .gnu.linkonce.sb.*)
        *(.scommon)
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
        . = ALIGN(4);
        __bss_end = .;
    } > kseg0

    __heap_start = .;

    __end = .;

    /DISCARD/ : { *(.MIPS.abiflags) }

    /* Everything is statically linked, so discard PLTs. */
    /DISCARD/ : { *(.rel.iplt) *(.rela.iplt) *(.rel.plt) *(.rela.plt) *(.plt) *(.iplt) }

    /* Discard things that the standard link script drops, too. */
    /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }

    /* This build-id section is causing objcopy issues, so let's throw it away too. */
    /DISCARD/ : { *(.note.gnu.build-id) }
}
