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

#pragma once

#include <stddef.h>
#include <stdint.h>

int psxdummy();

int psxtodigit(int c);
void psxatof(const char *str);
int psxabs(int j);
char *psxatob(char *str, int *result);
const char *psxstrpbrk(const char *s, const char *accepted);
unsigned psxstrspn(const char *s, const char *accepted);
unsigned psxstrcspn(const char *s, const char *rejected);
char *psxstrtok(char *str, const char *delim);
const char *psxbcopy(const void *src, void *dst, int n);
const char *psxbzero(void *ptr, int n);
int psxbcmp(const void *s1, const void *s2, int n);
uint32_t psxrand();
void psxsrand(uint32_t seed);
const void *psxlsearch(const char *key, const char *base, int nmemb, size_t size,
                       int (*compar)(const char *, const char *));
const void *psxbsearch(const char *key, const char *base, int nmemb, size_t size,
                       int (*compar)(const char *, const char *));
