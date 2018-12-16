/*
 * Copyright (c) 1995
 *	Ted Lemon (hereinafter referred to as the author)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __ECOFF_H__
#define __ECOFF_H__

#include "core/psxcommon.h"

/*
 * Some ECOFF definitions.
 */
typedef struct filehdr {
    u16 f_magic;  /* magic number */
    u16 f_nscns;  /* number of sections */
    u32 f_timdat; /* time & date stamp */
    u32 f_symptr; /* file pointer to symbolic header */
    u32 f_nsyms;  /* sizeof(symbolic hdr) */
    u16 f_opthdr; /* sizeof(optional hdr) */
    u16 f_flags;  /* flags */
} FILHDR;

typedef struct scnhdr {
    char s_name[8]; /* section name */
    u32 s_paddr;    /* physical address, aliased s_nlib */
    u32 s_vaddr;    /* virtual address */
    u32 s_size;     /* section size */
    u32 s_scnptr;   /* file s_ptr to raw data for section */
    u32 s_relptr;   /* file s_ptr to relocation */
    u32 s_lnnoptr;  /* file s_ptr to gp histogram */
    u16 s_nreloc;   /* number of relocation entries */
    u16 s_nlnno;    /* number of gp histogram entries */
    u32 s_flags;    /* flags */
} SCNHDR;

typedef struct aouthdr {
    u16 magic;      /* magic */
    u16 vstamp;     /* version stamp */
    u32 tsize;      /* text size in bytes, padded to DW bdry */
    u32 dsize;      /* initialized data */
    u32 bsize;      /* uninitialized data */
    u32 entry;      /* entry pt. */
    u32 text_start; /* base of text used for this file */
    u32 data_start; /* base of data used for this file */
} AOUTHDR;

#endif
