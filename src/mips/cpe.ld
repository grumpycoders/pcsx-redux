/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

OUTPUT_FORMAT("elf32-tradlittlemips")
OUTPUT_FORMAT("binary")

EXTERN(_start)
ENTRY(_start)

TLOAD_ADDR = DEFINED(_TLOAD_ADDR) ? TLOAD_ADDR : 0x80010000;

MEMORY {
    loader      : ORIGIN = 0x8000ffea, LENGTH = 22
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
    .CPE_Header : {
        BYTE(67); BYTE(80); BYTE(69); BYTE(1); 
        BYTE(8); BYTE(0);
        BYTE(3); BYTE(144); BYTE(0);
        LONG(ABSOLUTE(_start));
        BYTE(1);
        LONG(TLOAD_ADDR);
        LONG(__ftext_len + __fdata_len);
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
        __build_id = .;
        *(.note.gnu.build-id)
        __build_id_end = .;
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
    .data1 : {
        BYTE(0);
    } > ram
    . = ALIGN(4);
    __bss_start = .;
    .sbss (NOLOAD) : {
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

    /* Discard things that the standard link script drops, too. */
    /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }
}
