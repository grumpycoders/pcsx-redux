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
/*OUTPUT_ARCH("mips:3000")*/
OUTPUT_FORMAT("binary")

EXTERN(_start)
ENTRY(_start)

TLOAD_ADDR = DEFINED(_TLOAD_ADDR) ? TLOAD_ADDR : 0x80010000;

MEMORY {
    loader      : ORIGIN = 0x8000f800, LENGTH = 2048
    ram (rwx)   : ORIGIN = 0x80010000, LENGTH = 2M - 0x10000
    dcache      : ORIGIN = 0x1f800000, LENGTH = 0x400
}

__ram_top       = ORIGIN(ram) + LENGTH(ram);
__sp            = __ram_top - 0x100;

__dcache        = ORIGIN(dcache);
__dcache_top    = ORIGIN(dcache) + LENGTH(dcache);

__bss_len       = (__bss_end - __bss_start);
__ftext_len     = (__ftext_end - __ftext_start);
__fdata_len     = (__fdata_end - __fdata_start);

SECTIONS {
    .PSX_EXE_Header : {
        /*
            0x0000 - 0x0007 : "PS-X EXE"
        */
        BYTE(80); BYTE(83); BYTE(45); BYTE(88); BYTE(32); BYTE(69); BYTE(88); BYTE(69);

        /* 0x0008 - 0x000F : skip text_off and data_off since they're not supported by the PS1 BIOS */
        LONG(0); LONG(0);

        /* 0x0010 - 0x0013 : entry point */
        LONG(ABSOLUTE(_start));

        /* 0x0014 - 0x0017 : initial value of $gp */
        LONG(0);

        /* 0x0018 - 0x001B : Memory address to load "text" section to. */
        /*
            NOTE: The "text" section is actually all of the "load"
            sections of the file including .text, .rodata, .data.
            etc.
        */
        LONG(TLOAD_ADDR);

        /* 0x001C - 0x001F :  size, in bytes, of the "text" section. */
        LONG(__ftext_len + __fdata_len);

        /* 0x0020 - 0x002F :
            Skip "data_addr", "data_size", "bss_addr" and "bss_size".
            None of these are supported by retail PS1 BIOS.
        */
        LONG(0); LONG(0);
        LONG(0); LONG(0);

        /* 0x0030 - 0x0033 :  Initial stack address. */
        LONG(DEFINED(_sp) ? ABSOLUTE(_sp) : 0x801FFF00);

        /* 0x0034 - 0x0037 : Initial stack size, set it to 0. */
        LONG(0);

        /* Skip the remaining fields as they're not supported by the BIOS */
        . = . + 1992;
        /*
        . = ADDR(.text);
        */
    } > loader

    __ftext_start = ABSOLUTE(.);
    .text TLOAD_ADDR : {
        *(.start)
        *(.init)
        KEEP (*(SORT_NONE(.fini)))
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(.text .stub .text.* .gnu.linkonce.t.*)
        . = ALIGN(16);
    } > ram

    .fini : {
        . = ALIGN(16);
    } > ram

    . = ALIGN(16);
    __text_end = .;
    __ftext_end = ABSOLUTE(.);

    __fdata_start = ABSOLUTE(.);

    .rodata : {
        *(.rodata .rodata.* .rdata .rdata.* .gnu.linkonce.r.*)
    } > ram

    .rodata1 : {
        *(.rodata1)
    } > ram

    __data_start = .;
    .data : {
        *(.a0table)
        *(.data .data.* .gnu.linkonce.d.*)
        *(.data1)
        *(.got.plt)
        *(.got)
    } > ram

    . = ALIGN(4);
    __data_end = .;
    __fdata_end = .;
    __bss_start = .;
    .sbss : {
        *(.dynsbss)
        *(.sbss .sbss.* .gnu.linkonce.sb.*)
        *(.scommon)
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    } > ram

    . = ALIGN(4);
    __bss_end = .;

    __end = .;

    /* pad file to be a multiple of 2048 bytes.  Needed for loading from CD-ROM. */
   /* .__pad : { BYTE(0); . = ALIGN(2048); }*/
    . = ADDR(.text) - 0x800;


    /DISCARD/ : { *(.MIPS.abiflags) }

    /* Everything is statically linked, so discard PLTs. */
    /DISCARD/ : { *(.rel.iplt) *(.rela.iplt) *(.rel.plt) *(.rela.plt) *(.plt) *(.iplt) }

    /* We don't make use of debugging information, so drop that, too. */
    /DISCARD/ : { *(.debug) *(.debug_srcinfo) *(.debug_sfnames) *(.debug_aranges) *(.debug_pubnames) *(.debug_info .gnu.linkonce.wi.*) *(.debug_abbrev) *(.debug_line .debug_line.* .debug_line_end ) *(.debug_frame) *(.debug_str) *(.debug_loc) *(.debug_macinfo) *(.debug_weaknames) *(.debug_funcnames) *(.debug_typenames) *(.debug_varnames) *(.debug_pubtypes) *(.debug_ranges) *(.debug_macro) *(.mdebug.abi32) *(.mdebug.abiN32) *(.mdebug.abi64) *(.mdebug.abiO64) *(.mdebug.eabi32) *(.mdebug.eabi64) }

    /* Discard things that the standard link script drops, too. */
    /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }

    /DISCARD/ : { *(.note.gnu.build-id) }
}
