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

#include <ctype.h>
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "common/compiler/stdint.h"

int psxdummy() { return 0; }

int psxtodigit(int c) {
    if (!isxdigit(c)) return 9999999;
    if (isdigit(c)) return c - '0';
    return tolower(c) - 'a' + 10;
}

int psxabs(int j) {
    if (j >= 0) return j;
    return -j;
}

char * psxatob(char * str, int * result) {
    char * endp;
    *result = strtol(str, &endp, 10);
    return endp;
}

const char * psxstrpbrk(const char * s, const char * accepted) {
    char c;
    while ((c = *s)) {
        if (strchr(accepted, c)) return s;
        s++;
    }

    return NULL;
}

unsigned psxstrspn(const char * s, const char * accepted) {
    unsigned count = 0;
    unsigned maximum = 0;
    char c;
    while ((c = *s)) {
        if (strchr(accepted, c)) {
            count++;
            if (maximum < count) maximum = count;
        } else {
            count = 0;
        }
        s++;
    }

    return maximum;
}

unsigned psxstrcspn(const char * s, const char * rejected) {
    unsigned count = 0;
    unsigned maximum = 0;
    char c;
    while ((c = *s)) {
        if (!strchr(rejected, c)) {
            count++;
            if (maximum < count) maximum = count;
        } else {
            count = 0;
        }
        s++;
    }

    return maximum;
}

static char * s_strtokPtr;
char * psxstrtok(char * str, const char * delim) {
    char * oldPtr = str ? str : s_strtokPtr;
    if (str) {
        s_strtokPtr = psxstrpbrk(str, delim);
    } else {
        s_strtokPtr = psxstrpbrk(s_strtokPtr, delim);
    }
    if (s_strtokPtr) *s_strtokPtr = 0;
    return oldPtr;
}

const char * psxbcopy(const void * src, void * dst, int n) {
    if (!src) return NULL;
    if (n < 0) return src;
    memcpy(dst, src, n);
    return src;
}

const char * psxbzero(char * ptr, int n) {
    if (!ptr || n <= 0) return NULL;
    memset(ptr, 0, n);
    return ptr;
}

int psxbcmp(const void * s1, const void * s2, int n) {
    if (!s1 || !s2) return 0;
    return memcmp(s1, s2, n);
}

static uint32_t s_currentSeed;
uint32_t psxrand() {
    s_currentSeed = s_currentSeed * 1103515245 + 12345;
    return (s_currentSeed >> 16) & 0x7fff;
}

void psxsrand(uint32_t seed) {
    s_currentSeed = seed;
}

const void * psxlsearch(const char * key, const char * base, int nmemb, size_t size, int (*compar)(const char *, const char *)) {
    while (nmemb > 0) {
        if (compar(key, base) == 0) return base;
        nmemb--;
    };
    return NULL;
}

const void * psxbsearch(const char * key, const char * base, int nmemb, size_t size, int (*compar)(const char *, const char*)) {
    int lo = 0;
    int hi = nmemb;
    int needle;
    while (lo < hi) {
        int needle = (hi - lo) >> 1;
        const char * ptr = base + needle * size;
        int direction = compar(ptr, key);
        if (direction == 0) return ptr;
        if (direction < 0) {
            hi = needle - 1;
        } else {
            lo = needle + 1;
        }
    }
    return NULL;
}
