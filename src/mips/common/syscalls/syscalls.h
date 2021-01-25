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

#include <stdarg.h>
#include <stddef.h>

#include "common/compiler/stdint.h"
#include "common/psxlibc/circularbuffer.h"
#include "common/psxlibc/device.h"
#include "common/psxlibc/handlers.h"

struct JmpBuf;

static __attribute__((always_inline)) int enterCriticalSection() {
    register int n asm("a0") = 1;
    register int r asm("v0");
    __asm__ volatile("syscall\n"
                     : "=r"(n), "=r"(r)
                     : "r"(n)
                     : "at", "v1", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9",
                       "memory");
    return r;
}

static __attribute__((always_inline)) void leaveCriticalSection() {
    register int n asm("a0") = 2;
    __asm__ volatile("syscall\n"
                     : "=r"(n)
                     : "r"(n)
                     : "at", "v0", "v1", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9",
                       "memory");
}

static __attribute__((always_inline)) int changeThreadSubFunction(uint32_t address) {
    register int n asm("a0") = 3;
    register int tcb asm("a1") = address;
    register int r asm("v0");
    __asm__ volatile("syscall\n"
                     : "=r"(r), "=r"(n), "=r"(tcb)
                     : "r"(n), "r"(tcb)
                     : "at", "v1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory");
    return r;
}

/* A0 table */
static __attribute__((always_inline)) int syscall_setjmp(struct JmpBuf *buf) {
    register int n asm("t1") = 0x13;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(struct JmpBuf * buf))0xa0)(buf);
}

static __attribute__((always_inline)) __attribute__((noreturn)) void syscall_longjmp(struct JmpBuf *buf, int ret) {
    register int n asm("t1") = 0x14;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(struct JmpBuf *, int))0xa0)(buf, ret);
}

static __attribute__((always_inline)) char *syscall_strcat(char *dst, const char *src) {
    register int n asm("t1") = 0x15;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(char *, const char *))0xa0)(dst, src);
}

static __attribute__((always_inline)) char *syscall_strncat(char *dst, const char *src, size_t size) {
    register int n asm("t1") = 0x16;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(char *, const char *, size_t))0xa0)(dst, src, size);
}

static __attribute__((always_inline)) int syscall_strcmp(const char *s1, const char *s2) {
    register int n asm("t1") = 0x17;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(const char *, const char *))0xa0)(s1, s2);
}

static __attribute__((always_inline)) int syscall_strncmp(const char *s1, const char *s2, size_t size) {
    register int n asm("t1") = 0x18;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(const char *, const char *, size_t))0xa0)(s1, s2, size);
}

static __attribute__((always_inline)) char *syscall_strcpy(char *dst, const char *src) {
    register int n asm("t1") = 0x19;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(char *, const char *))0xa0)(dst, src);
}

static __attribute__((always_inline)) char *syscall_strncpy(char *dst, const char *src, size_t size) {
    register int n asm("t1") = 0x1a;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(char *, const char *, size_t))0xa0)(dst, src, size);
}

static __attribute__((always_inline)) size_t syscall_strlen(const char *s) {
    register int n asm("t1") = 0x1b;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((size_t(*)(const char *))0xa0)(s);
}

static __attribute__((always_inline)) char *syscall_index(const char *s, int c) {
    register int n asm("t1") = 0x1c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(const char *, int c))0xa0)(s, c);
}

static __attribute__((always_inline)) char *syscall_rindex(const char *s, int c) {
    register int n asm("t1") = 0x1d;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(const char *, int c))0xa0)(s, c);
}

static __attribute__((always_inline)) char *syscall_strchr(const char *s, int c) {
    register int n asm("t1") = 0x1e;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(const char *, int c))0xa0)(s, c);
}

static __attribute__((always_inline)) char *syscall_strrchr(const char *s, int c) {
    register int n asm("t1") = 0x1f;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((char *(*)(const char *, int c))0xa0)(s, c);
}

static __attribute__((always_inline)) void *syscall_memcpy(void *dst, const void *src, size_t count) {
    register int n asm("t1") = 0x2a;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void *(*)(void *, const void *, size_t))0xa0)(dst, src, count);
}

static __attribute__((always_inline)) void *syscall_memset(void *dst, int c, size_t count) {
    register int n asm("t1") = 0x2b;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void *(*)(void *, int, size_t))0xa0)(dst, c, count);
}

static __attribute__((always_inline)) void syscall_qsort(void *base, size_t nel, size_t width,
                                                         int (*compar)(const void *, const void *)) {
    register int n asm("t1") = 0x31;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(void *, size_t, size_t, int (*)(const void *, const void *)))0xa0)(base, nel, width, compar);
}

static __attribute__((always_inline)) void syscall__exit(int code) {
    register int n asm("t1") = 0x3a;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(int))0xa0)(code);
}

// doing this one in raw inline assembly would prove tricky,
// and there's already enough voodoo in this file.
// this is syscall a0:3f
int romsyscall_printf(const char *fmt, ...);
int ramsyscall_printf(const char *fmt, ...);

static __attribute__((always_inline)) int syscall_unresolvedException() {
    register int n asm("t1") = 0x40;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)())0xa0)();
}

static __attribute__((always_inline)) void syscall_flushCache() {
    register int n asm("t1") = 0x44;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void (*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_cdromSeekL(uint8_t *msf) {
    register int n asm("t1") = 0x78;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(uint8_t *))0xa0)(msf);
}

static __attribute__((always_inline)) int syscall_cdromGetStatus(uint8_t *ptr) {
    register int n asm("t1") = 0x7c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(uint8_t *))0xa0)(ptr);
}

static __attribute__((always_inline)) int syscall_cdromRead(int count, char *buffer, uint32_t mode) {
    register int n asm("t1") = 0x7e;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int, char *, uint32_t))0xa0)(count, buffer, mode);
}

static __attribute__((always_inline)) int syscall_cdromInnerInit() {
    register int n asm("t1") = 0x95;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addCDRomDevice() {
    register int n asm("t1") = 0x96;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addMemoryCardDevice() {
    register int n asm("t1") = 0x97;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addConsoleDevice() {
    register int n asm("t1") = 0x98;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addDummyConsoleDevice() {
    register int n asm("t1") = 0x99;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)())0xa0)();
}

static __attribute__((always_inline)) void syscall_exception(int code1, int code2) {
    register int n asm("t1") = 0xa1;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(int, int))0xa0)(code1, code2);
}

static __attribute__((always_inline)) void syscall_enqueueCDRomHandlers() {
    register int n asm("t1") = 0xa2;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)())0xa0)();
}

static __attribute__((always_inline)) void syscall_dequeueCDRomHandlers() {
    register int n asm("t1") = 0xa3;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_ioabortraw(int code) {
    register int n asm("t1") = 0xb2;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((int (*)(int))0xa0)(code);
}

/* B0 table */
static __attribute__((always_inline)) void *syscall_kmalloc(unsigned size) {
    register int n asm("t1") = 0x00;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void *(*)(unsigned))0xb0)(size);
}

static __attribute__((always_inline)) void syscall_kfree(void *ptr) {
    register int n asm("t1") = 0x01;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void (*)(void *))0xb0)(ptr);
}

static __attribute__((always_inline)) void syscall_deliverEvent(uint32_t class, uint32_t spec) {
    register int n asm("t1") = 0x07;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(uint32_t, uint32_t))0xb0)(class, spec);
}

static __attribute__((always_inline)) uint32_t syscall_openEvent(uint32_t class, uint32_t spec, uint32_t mode,
                                                                 void *handler) {
    register int n asm("t1") = 0x08;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((uint32_t(*)(uint32_t, uint32_t, uint32_t, void *))0xb0)(class, spec, mode, handler);
}

static __attribute__((always_inline)) int syscall_closeEvent(uint32_t event) {
    register int n asm("t1") = 0x09;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((uint32_t(*)(uint32_t))0xb0)(event);
}

static __attribute__((always_inline)) int syscall_testEvent(uint32_t event) {
    register int n asm("t1") = 0x0b;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(uint32_t))0xb0)(event);
}

static __attribute__((always_inline)) int syscall_enableEvent(uint32_t event) {
    register int n asm("t1") = 0x0c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(uint32_t))0xb0)(event);
}

static __attribute__((noreturn)) __attribute__((always_inline)) void syscall_returnFromException() {
    register int n asm("t1") = 0x17;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((__attribute__((noreturn)) void (*)())0xb0)();
}

static __attribute__((always_inline)) void syscall_setDefaultExceptionJmpBuf() {
    register int n asm("t1") = 0x18;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)())0xb0)();
}

static __attribute__((always_inline)) void syscall_undeliverEvent(uint32_t class, uint32_t mode) {
    register int n asm("t1") = 0x20;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(uint32_t, uint32_t))0xb0)(class, mode);
}

static __attribute__((always_inline)) int syscall_open(const char *filename, int mode) {
    register int n asm("t1") = 0x32;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(const char *, int))0xb0)(filename, mode);
}

static __attribute__((always_inline)) int syscall_read(int fd, void *buffer, int size) {
    register int n asm("t1") = 0x34;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int, void *, int))0xb0)(fd, buffer, size);
}

static __attribute__((always_inline)) int syscall_close(int fd) {
    register int n asm("t1") = 0x36;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int))0xb0)(fd);
}

static __attribute__((always_inline)) void syscall_putchar(int c) {
    register int n asm("t1") = 0x3d;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(int))0xb0)(c);
}

static __attribute__((always_inline)) int syscall_addDevice(const struct Device *device) {
    register int n asm("t1") = 0x47;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((int (*)(const struct Device *))0xb0)(device);
}

/* C0 table */
static __attribute__((always_inline)) int syscall_enqueueRCntIrqs(int priority) {
    register int n asm("t1") = 0x00;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int))0xc0)(priority);
}

static __attribute__((always_inline)) int syscall_enqueueSyscallHandler(int priority) {
    register int n asm("t1") = 0x01;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int))0xc0)(priority);
}

static __attribute__((always_inline)) int syscall_sysEnqIntRP(int priority, struct HandlerInfo *info) {
    register int n asm("t1") = 0x02;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int, struct HandlerInfo *))0xc0)(priority, info);
}

static __attribute__((always_inline)) int syscall_sysDeqIntRP(int priority, struct HandlerInfo *info) {
    register int n asm("t1") = 0x03;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int, struct HandlerInfo *))0xc0)(priority, info);
}

static __attribute__((always_inline)) void syscall_installExceptionHandler() {
    register int n asm("t1") = 0x07;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)())0xc0)();
}

static __attribute__((always_inline)) int syscall_enqueueIrqHandler(int priority) {
    register int n asm("t1") = 0x0c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(int))0xc0)(priority);
}

static __attribute__((always_inline)) void syscall_setupFileIO(int installTTY) {
    register int n asm("t1") = 0x12;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(int))0xc0)(installTTY);
}

static __attribute__((always_inline)) void syscall_cdevinput(struct CircularBuffer *circ, int c) {
    register int n asm("t1") = 0x15;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)(struct CircularBuffer *, int))0xc0)(circ, c);
}

static __attribute__((always_inline)) void syscall_cdevscan() {
    register int n asm("t1") = 0x16;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)())0xc0)();
}

static __attribute__((always_inline)) int syscall_circgetc(struct CircularBuffer *circ) {
    register int n asm("t1") = 0x17;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(struct CircularBuffer *))0xc0)(circ);
}

static __attribute__((always_inline)) int syscall_ioabort(const char *msg) {
    register int n asm("t1") = 0x19;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int (*)(const char *))0xc0)(msg);
}

static __attribute__((always_inline)) int syscall_patchA0table() {
    register int n asm("t1") = 0x1c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void (*)())0xc0)();
}
