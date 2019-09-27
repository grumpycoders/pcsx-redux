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

EXTERN(_start)
ENTRY(_start)

MEMORY {
    ram (rwx)   : ORIGIN = 0x80010000, LENGTH = 2M - 0x10000
    dcache      : ORIGIN = 0x1f800000, LENGTH = 0x400
}

__ram_top       = ORIGIN(ram) + LENGTH(ram);
__sp            = __ram_top - 0x100;

__dcache        = ORIGIN(dcache);
__dcache_top    = ORIGIN(dcache) + LENGTH(dcache);

__bss_len       = (__bss_end - __bss_start);

SECTIONS {
    __text_start = .;
    .text : {
        *(.start)
        *(.init)
        KEEP (*(SORT_NONE(.fini)))
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(.text .stub .text.* .gnu.linkonce.t.*)
        . = ALIGN(4);
    } > ram

    .fini : {
    } > ram
    . = ALIGN(4);
    __text_end = .;

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

    /DISCARD/ : { *(.MIPS.abiflags) }

    /* Everything is statically linked, so discard PLTs. */
    /DISCARD/ : { *(.rel.iplt) *(.rela.iplt) *(.rel.plt) *(.rela.plt) *(.plt) *(.iplt) }

    /* We don't make use of debugging information, so drop that, too. */
    /DISCARD/ : { *(.debug) *(.debug_srcinfo) *(.debug_sfnames) *(.debug_aranges) *(.debug_pubnames) *(.debug_info .gnu.linkonce.wi.*) *(.debug_abbrev) *(.debug_line .debug_line.* .debug_line_end ) *(.debug_frame) *(.debug_str) *(.debug_loc) *(.debug_macinfo) *(.debug_weaknames) *(.debug_funcnames) *(.debug_typenames) *(.debug_varnames) *(.debug_pubtypes) *(.debug_ranges) *(.debug_macro) *(.mdebug.abi32) *(.mdebug.abiN32) *(.mdebug.abi64) *(.mdebug.abiO64) *(.mdebug.eabi32) *(.mdebug.eabi64) }

    /* Discard things that the standard link script drops, too. */
    /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }

    /DISCARD/ : { *(.note.gnu.build-id) }
}
