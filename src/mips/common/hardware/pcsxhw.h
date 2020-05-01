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

#include <stdint.h>

static __inline__ void pcsx_putc(int c) { *((volatile char * const) 0x1f802080) = c; }
static __inline__ void pcsx_debugbreak() { *((volatile char * const) 0x1f802081) = 0; }
static __inline__ void pcsx_exit(int code) { *((volatile int16_t * const) 0x1f802082) = code; }

static __inline__ int pcsx_present() {
    return *((volatile uint32_t * const) 0x1f802080) == 0x58534350;
}
