/*
 * Copyright (c) 1995
 *  Ted Lemon (hereinafter referred to as the author)
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

#include "core/psxemulator.h"

/*
 * Some ECOFF definitions.
 */
typedef struct filehdr {
    uint16_t f_magic;  /* magic number */
    uint16_t f_nscns;  /* number of sections */
    uint32_t f_timdat; /* time & date stamp */
    uint32_t f_symptr; /* file pointer to symbolic header */
    uint32_t f_nsyms;  /* sizeof(symbolic hdr) */
    uint16_t f_opthdr; /* sizeof(optional hdr) */
    uint16_t f_flags;  /* flags */
} FILHDR;

typedef struct scnhdr {
    char s_name[8];     /* section name */
    uint32_t s_paddr;   /* physical address, aliased s_nlib */
    uint32_t s_vaddr;   /* virtual address */
    uint32_t s_size;    /* section size */
    uint32_t s_scnptr;  /* file s_ptr to raw data for section */
    uint32_t s_relptr;  /* file s_ptr to relocation */
    uint32_t s_lnnoptr; /* file s_ptr to gp histogram */
    uint16_t s_nreloc;  /* number of relocation entries */
    uint16_t s_nlnno;   /* number of gp histogram entries */
    uint32_t s_flags;   /* flags */
} SCNHDR;

typedef struct aouthdr {
    uint16_t magic;      /* magic */
    uint16_t vstamp;     /* version stamp */
    uint32_t tsize;      /* text size in bytes, padded to DW bdry */
    uint32_t dsize;      /* initialized data */
    uint32_t bsize;      /* uninitialized data */
    uint32_t entry;      /* entry pt. */
    uint32_t text_start; /* base of text used for this file */
    uint32_t data_start; /* base of data used for this file */
} AOUTHDR;

#endif
