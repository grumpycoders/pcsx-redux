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

struct Registers {
    union {
        struct {
            uint32_t r0, at, v0, v1, a0, a1, a2, a3;
            uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
            uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
            uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
        } n;
        uint32_t r[32];
    } GPR;
    uint32_t returnPC;
    uint32_t hi, lo;
    uint32_t SR;
    uint32_t Cause;
};

struct Thread {
    uint32_t flags, flags2;
    struct Registers registers;
    uint32_t unknown[9];
};

int initThreads(int blocks, int count);
