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

#include <stdarg.h>

static __inline__ int syscall_strcmp(const char * s1, const char * s2) {
    register volatile int n asm("t1") = 0x17;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)(const char * s1, const char * s2))0xa0)(s1, s2);
}

static __inline__ void syscall__exit() {
    register volatile int n asm("t1") = 0x3a;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)())0xa0)();
}

// doing this one in raw inline assembly would prove tricky,
// and there's already enough voodoo in this file.
// this is syscall a0:3f
int syscall_printf(const char * fmt, ...);

static __inline__ int syscall_addConsoleDevice() {
    register volatile int n asm("t1") = 0x98;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __inline__ int syscall_addDummyConsoleDevice() {
    register volatile int n asm("t1") = 0x99;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((int(*)())0xa0)();
}

static __inline__ void syscall_ioabort(int code) {
    register volatile int n asm("t1") = 0xb2;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)())0xa0)(code);
}

static __inline__ void syscall_setDefaultExceptionJmpBuf() {
    register volatile int n asm("t1") = 0x18;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)())0xb0)();
}

static __inline__ void syscall_putchar(int c) {
    register volatile int n asm("t1") = 0x3d;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)(int))0xb0)(c);
}

static __inline__ void syscall_installExceptionHandler() {
    register volatile int n asm("t1") = 0x07;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)())0xc0)();
}

static __inline__ void syscall_setupFileIO(int installTTY) {
    register volatile int n asm("t1") = 0x12;
    __asm__ volatile("" : "=r"(n) : "r"(n));
    return ((void(*)(int))0xc0)(installTTY);
}
