/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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

#pragma once

#include <stddef.h>

#include "common/compiler/stdint.h"

int psxdummy();

int psxtodigit(int c);
void psxatof(const char * str);
int psxabs(int j);
char * psxatob(char * str, int * result);
const char * psxstrpbrk(const char * s, const char * accepted);
unsigned psxstrspn(const char * s, const char * accepted);
unsigned psxstrcspn(const char * s, const char * rejected);
char * psxstrtok(char * str, const char * delim);
const char * psxbcopy(const void * src, void * dst, int n);
const char * psxbzero(void * ptr, int n);
int psxbcmp(const void * s1, const void * s2, int n);
uint32_t psxrand();
void psxsrand(uint32_t seed);
const void * psxlsearch(const char * key, const char * base, int nmemb, size_t size, int (*compar)(const char *, const char *));
const void * psxbsearch(const char * key, const char * base, int nmemb, size_t size, int (*compar)(const char *, const char *));
