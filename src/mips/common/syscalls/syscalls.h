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
    register const char * arg1 asm("a0") = s1;
    register const char * arg2 asm("a1") = s2;
    register int ret asm("v0");
    __asm__ volatile(
        "li $t2, 0xa0\n"
        "li $t1, 0x17\n"
        "jr $t2\n"
        : "=r"(ret), "=r"(arg1), "=r"(arg2)
        : "r"(arg1), "r"(arg2)
        : "a2", "a3", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
    return ret;
}

// doing this one in raw inline assembly would prove tricky,
// and there's already enough voodoo in this file.
// this is syscall a0:3f
int syscall_printf(const char * fmt, ...);

static __inline__ int syscall_addConsoleDevice() {
    register int ret asm("v0");
    __asm__ volatile(
        "li $t2, 0xa0\n"
        "li $t1, 0x98\n"
        "jr $t2\n"
        : "=r"(ret)
        :
        : "a0", "a1", "a2", "a3", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
    return ret;
}

static __inline__ int syscall_addDummyConsoleDevice() {
    register int ret asm("v0");
    __asm__ volatile(
        "li $t2, 0xa0\n"
        "li $t1, 0x99\n"
        "jr $t2\n"
        : "=r"(ret)
        :
        : "a0", "a1", "a2", "a3", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
    return ret;
}

static __inline__ void syscall_ioabort(int code) {
    register int arg asm("a0") = code;
    __asm__ volatile(
        "li $t2, 0xa0\n"
        "li $t1, 0xb2\n"
        "jr $t2\n"
        : "=r"(arg)
        : "r"(arg)
        : "a1", "a2", "a3", "v0", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
}

static __inline__ void syscall_setDefaultExceptionJmpBuf() {
    __asm__ volatile(
        "li $t2, 0xb0\n"
        "li $t1, 0x18\n"
        "jr $t2\n"
        :
        :
        : "a0", "a1", "a2", "a3", "v0", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
}

static __inline__ void syscall_putchar(int c) {
    register int arg asm("a0") = c;
    __asm__ volatile(
        "li $t2, 0xb0\n"
        "li $t1, 0x3d\n"
        "jr $t2\n"
        : "=r"(arg)
        : "r"(arg)
        : "a1", "a2", "a3", "v0", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
}

static __inline__ void syscall_installExceptionHandler() {
    __asm__ volatile(
        "li $t2, 0xc0\n"
        "li $t1, 0x07\n"
        "jr $t2\n"
        :
        :
        : "a0", "a1", "a2", "a3", "v0", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
}

static __inline__ void syscall_setupFileIO(int installTTY) {
    register int arg asm("a0") = installTTY;
    __asm__ volatile(
        "li $t2, 0xc0\n"
        "li $t1, 0x12\n"
        "jr $t2\n"
        : "=r"(arg)
        : "r"(arg)
        : "a1", "a2", "a3", "v0", "v1", "at", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "memory"
    );
}
