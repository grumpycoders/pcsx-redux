/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include <ctype.h>
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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

char *psxatob(char *str, int *result) {
    char *endp;
    *result = strtol(str, &endp, 10);
    return endp;
}

const char *psxstrpbrk(const char *s, const char *accepted) {
    char c;
    while ((c = *s)) {
        if (strchr(accepted, c)) return s;
        s++;
    }

    return NULL;
}

unsigned psxstrspn(const char *s, const char *accepted) {
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

unsigned psxstrcspn(const char *s, const char *rejected) {
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

static char *s_strtokPtr;
char *psxstrtok(char *str, const char *delim) {
    char *oldPtr = str ? str : s_strtokPtr;
    if (str) {
        s_strtokPtr = psxstrpbrk(str, delim);
    } else {
        s_strtokPtr = psxstrpbrk(s_strtokPtr, delim);
    }
    if (s_strtokPtr) *s_strtokPtr = 0;
    return oldPtr;
}

const void *psxbcopy(const void *src, void *dst, int n) {
    if (!src) return NULL;
    if (n < 0) return src;
    memcpy(dst, src, n);
    return src;
}

const void *psxbzero(void *ptr, int n) {
    if (!ptr || n <= 0) return NULL;
    memset(ptr, 0, n);
    return ptr;
}

int psxbcmp(const void *s1, const void *s2, int n) {
    if (!s1 || !s2) return 0;
    return memcmp(s1, s2, n);
}

static uint32_t s_currentSeed;
uint32_t psxrand() {
    s_currentSeed = s_currentSeed * 1103515245 + 12345;
    return (s_currentSeed >> 16) & 0x7fff;
}

void psxsrand(uint32_t seed) { s_currentSeed = seed; }

const void *psxlsearch(const char *key, const char *base, int nmemb, size_t size,
                       int (*compar)(const char *, const char *)) {
    while (nmemb-- > 0)
        if (compar(key, base) == 0) return base;
    return NULL;
}

const void *psxbsearch(const char *key, const char *base, int nmemb, size_t size,
                       int (*compar)(const char *, const char *)) {
    int lo = 0;
    int hi = nmemb;
    int needle;
    while (lo < hi) {
        int needle = (hi - lo) >> 1;
        const char *ptr = base + needle * size;
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
