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

static __attribute__((always_inline)) int enterCriticalSection() {
    register volatile int n asm("a0") = 1;
    register volatile int r asm("v0");
    __asm__ volatile("syscall\n" : "=r"(n), "=r"(r) : "r"(n) : "at", "v1", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory");
    return r;
}

static __attribute__((always_inline)) void leaveCriticalSection() {
    register volatile int n asm("a0") = 2;
    __asm__ volatile("syscall\n" : "=r"(n) : "r"(n) : "at", "v0", "v1", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory");
}

/* A0 table */
static __attribute__((always_inline)) int syscall_strcmp(const char * s1, const char * s2) {
    register volatile int n asm("t1") = 0x17;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(const char * s1, const char * s2))0xa0)(s1, s2);
}

static __attribute__((always_inline)) void * syscall_memcpy(void * dst, const void * src, size_t count) {
    register volatile int n asm("t1") = 0x2a;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void *(*)(void *, const void *, size_t))0xa0)(dst, src, count);
}

static __attribute__((always_inline)) void syscall__exit() {
    register volatile int n asm("t1") = 0x3a;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)())0xa0)();
}

// doing this one in raw inline assembly would prove tricky,
// and there's already enough voodoo in this file.
// this is syscall a0:3f
int romsyscall_printf(const char * fmt, ...);
int ramsyscall_printf(const char * fmt, ...);

static __attribute__((always_inline)) int syscall_unresolvedException() {
    register volatile int n asm("t1") = 0x40;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __attribute__((always_inline)) void syscall_flushCache() {
    register volatile int n asm("t1") = 0x44;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_cdromSeekL(uint8_t * msf) {
    register volatile int n asm("t1") = 0x78;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(uint8_t *))0xa0)(msf);
}

static __attribute__((always_inline)) int syscall_cdromGetStatus(uint8_t * ptr) {
    register volatile int n asm("t1") = 0x7c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(uint8_t *))0xa0)(ptr);
}

static __attribute__((always_inline)) int syscall_cdromRead(int count, char * buffer, uint32_t mode) {
    register volatile int n asm("t1") = 0x7e;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int, char *, uint32_t))0xa0)(count, buffer, mode);
}

static __attribute__((always_inline)) int syscall_cdromInnerInit() {
    register volatile int n asm("t1") = 0x95;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addCDRomDevice() {
    register volatile int n asm("t1") = 0x96;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addMemoryCardDevice() {
    register volatile int n asm("t1") = 0x97;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addConsoleDevice() {
    register volatile int n asm("t1") = 0x98;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_addDummyConsoleDevice() {
    register volatile int n asm("t1") = 0x99;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __attribute__((always_inline)) void syscall_exception(int code1, int code2) {
    register volatile int n asm("t1") = 0xa1;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)(int, int))0xa0)(code1, code2);
}

static __attribute__((always_inline)) void syscall_enqueueCDRomHandlers() {
    register volatile int n asm("t1") = 0xa2;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)())0xa0)();
}

static __attribute__((always_inline)) void syscall_dequeueCDRomHandlers() {
    register volatile int n asm("t1") = 0xa3;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)())0xa0)();
}

static __attribute__((always_inline)) int syscall_ioabortraw(int code) {
    register volatile int n asm("t1") = 0xb2;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((int(*)(int))0xa0)(code);
}

/* B0 table */
static __attribute__((always_inline)) void * syscall_kmalloc(unsigned size) {
    register volatile int n asm("t1") = 0x00;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void*(*)(unsigned))0xb0)(size);
}

static __attribute__((always_inline)) void syscall_kfree(void * ptr) {
    register volatile int n asm("t1") = 0x01;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)(void *))0xb0)(ptr);
}

static __attribute__((always_inline)) void syscall_deliverEvent(uint32_t class, uint32_t mode) {
    register volatile int n asm("t1") = 0x07;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)(uint32_t, uint32_t))0xb0)(class, mode);
}

static __attribute__((always_inline)) uint32_t syscall_openEvent(uint32_t class, uint32_t spec, uint32_t mode, void * handler) {
    register volatile int n asm("t1") = 0x08;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((uint32_t(*)(uint32_t, uint32_t, uint32_t, void *))0xb0)(class, spec, mode, handler);
}

static __attribute__((always_inline)) int syscall_closeEvent(uint32_t event) {
    register volatile int n asm("t1") = 0x09;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((uint32_t(*)(uint32_t))0xb0)(event);
}

static __attribute__((always_inline)) int syscall_testEvent(uint32_t event) {
    register volatile int n asm("t1") = 0x0b;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(uint32_t))0xb0)(event);
}

static __attribute__((always_inline)) int syscall_enableEvent(uint32_t event) {
    register volatile int n asm("t1") = 0x0c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(uint32_t))0xb0)(event);
}

static __attribute__((noreturn)) __attribute__((always_inline)) void syscall_returnFromException() {
    register volatile int n asm("t1") = 0x17;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((__attribute__((noreturn)) void(*)())0xb0)();
}

static __attribute__((always_inline)) void syscall_setDefaultExceptionJmpBuf() {
    register volatile int n asm("t1") = 0x18;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)())0xb0)();
}

static __attribute__((always_inline)) void syscall_undeliverEvent(uint32_t class, uint32_t mode) {
    register volatile int n asm("t1") = 0x20;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)(uint32_t, uint32_t))0xb0)(class, mode);
}

static __attribute__((always_inline)) int syscall_open(const char * filename, int mode) {
    register volatile int n asm("t1") = 0x32;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(const char *, int))0xb0)(filename, mode);
}

static __attribute__((always_inline)) int syscall_read(int fd, void * buffer, int size) {
    register volatile int n asm("t1") = 0x34;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int, void *, int))0xb0)(fd, buffer, size);
}

static __attribute__((always_inline)) int syscall_close(int fd) {
    register volatile int n asm("t1") = 0x36;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int))0xb0)(fd);
}

static __attribute__((always_inline)) void syscall_putchar(int c) {
    register volatile int n asm("t1") = 0x3d;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)(int))0xb0)(c);
}

static __attribute__((always_inline)) int syscall_addDevice(const struct Device * device) {
    register volatile int n asm("t1") = 0x47;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((int(*)(const struct Device *))0xb0)(device);
}

/* C0 table */
static __attribute__((always_inline)) int syscall_enqueueRCntIrqs(int priority) {
    register volatile int n asm("t1") = 0x00;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int))0xc0)(priority);
}

static __attribute__((always_inline)) int syscall_enqueueSyscallHandler(int priority) {
    register volatile int n asm("t1") = 0x01;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int))0xc0)(priority);
}

static __attribute__((always_inline)) int syscall_sysEnqIntRP(int priority, struct HandlerInfo * info) {
    register volatile int n asm("t1") = 0x02;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int, struct HandlerInfo *))0xc0)(priority, info);
}

static __attribute__((always_inline)) int syscall_sysDeqIntRP(int priority, struct HandlerInfo * info) {
    register volatile int n asm("t1") = 0x03;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int, struct HandlerInfo *))0xc0)(priority, info);
}

static __attribute__((always_inline)) void syscall_installExceptionHandler() {
    register volatile int n asm("t1") = 0x07;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)())0xc0)();
}

static __attribute__((always_inline)) int syscall_enqueueIrqHandler(int priority) {
    register volatile int n asm("t1") = 0x0c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(int))0xc0)(priority);
}

static __attribute__((always_inline)) void syscall_setupFileIO(int installTTY) {
    register volatile int n asm("t1") = 0x12;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)(int))0xc0)(installTTY);
}

static __attribute__((always_inline)) void syscall_cdevinput(struct CircularBuffer * circ, int c) {
    register volatile int n asm("t1") = 0x15;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)(struct CircularBuffer *, int))0xc0)(circ, c);
}

static __attribute__((always_inline)) void syscall_cdevscan() {
    register volatile int n asm("t1") = 0x16;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)())0xc0)();
}

static __attribute__((always_inline)) int syscall_circgetc(struct CircularBuffer * circ) {
    register volatile int n asm("t1") = 0x17;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(struct CircularBuffer *))0xc0)(circ);
}

static __attribute__((always_inline)) int syscall_ioabort(const char * msg) {
    register volatile int n asm("t1") = 0x19;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(const char *))0xc0)(msg);
}

static __attribute__((always_inline)) int syscall_patchA0table() {
    register volatile int n asm("t1") = 0x1c;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    ((void(*)())0xc0)();
}
