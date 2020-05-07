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

#include <memory.h>

#include "common/compiler/stdint.h"
#include "openbios/kernel/flushcache.h"
#include "openbios/shell/shell.h"

#define NOP()  0x00000000
#define JRRA() 0x03e00008

static uint32_t s_shellCode[] = {
    JRRA(),
    NOP(),
};

int startShell(uint32_t arg) {
    memcpy((uint32_t *) 0x80030000, s_shellCode, sizeof(s_shellCode));
    flushCache();
    return ((int(*)(int)) 0x80030000)(arg);
}
