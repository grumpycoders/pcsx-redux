/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

// This is a reverse of the libsn pcdrv API. It doesn't make a lot of sense.

static inline int PCinit() {
    register int r asm("v0");
    __asm__ volatile("break 0, 0x101\n" : "=r"(r));
    return r;
}

static inline int PCcreat(const char *name, int perms) {
    register const char *a0 asm("a0") = name;
    register const char *a1 asm("a1") = name;
    register int a2 asm("a2") = 0;
    register int v0 asm("v0");
    register int v1 asm("v1");
    __asm__ volatile("break 0, 0x102\n" : "=r"(v0), "=r"(v1) : "r"(a0), "r"(a1), "r"(a2));
    if (v0 == 0) return v1;
    return -1;
}

static inline int PCopen(char *name, int flags, int perms) {
    register int a2 asm("a2") = flags;
    register const char *a0 asm("a0") = name;
    register const char *a1 asm("a1") = name;
    register int v0 asm("v0");
    register int v1 asm("v1");
    __asm__ volatile("break 0, 0x103\n" : "=r"(v0), "=r"(v1) : "r"(a0), "r"(a1), "r"(a2));
    if (v0 == 0) return v1;
    return -1;
}

static inline int PCclose(int fd) {
    register int a0 asm("a0") = fd;
    register int a1 asm("a1") = fd;
    register int v0 asm("v0");
    __asm__ volatile("break 0, 0x104\n" : "=r"(v0) : "r"(a0), "r"(a1) : "v1");
    return v0;
}

static inline int PCread(int fd, void *buf, int len) {
    register int a0 asm("a0") = 0;
    register int a1 asm("a1") = fd;
    register int a2 asm("a2") = len;
    register void *a3 asm("a3") = buf;
    register int v0 asm("v0");
    register int v1 asm("v1");
    __asm__ volatile("break 0, 0x105\n" : "=r"(v0), "=r"(v1) : "r"(a0), "r"(a1), "r"(a2), "r"(a3) : "memory");
    if (v0 == 0) return v1;
    return -1;
}

static inline int PCwrite(int fd, const void *buf, int len) {
    register int a0 asm("a0") = 0;
    register int a1 asm("a1") = fd;
    register int a2 asm("a2") = len;
    register const void *a3 asm("a3") = buf;
    register int v0 asm("v0");
    register int v1 asm("v1");
    __asm__ volatile("break 0, 0x106\n" : "=r"(v0), "=r"(v1) : "r"(a0), "r"(a1), "r"(a2), "r"(a3));
    if (v0 == 0) return v1;
    return -1;
}

static inline int PClseek(int fd, int offset, int wheel) {
    register int a3 asm("a3") = wheel;
    register int a2 asm("a2") = offset;
    register int a0 asm("a0") = fd;
    register int a1 asm("a1") = fd;
    register int v0 asm("v0");
    register int v1 asm("v1");
    __asm__ volatile("break 0, 0x107\n" : "=r"(v0), "=r"(v1) : "r"(a0), "r"(a1), "r"(a2), "r"(a3));
    if (v0 == 0) return v1;
    return -1;
}
