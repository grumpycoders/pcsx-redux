/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include "common/hardware/hwregs.h"
#include "common/compiler/stdint.h"

#define SIO1_DATA HW_U8(0x1f801050)
#define SIO1_STAT HW_U16(0x1f801054)
#define SIO1_MODE HW_U16(0x1f801058)
#define SIO1_CTRL HW_U16(0x1f80105a)
#define SIO1_BAUD HW_U16(0x1f80105e)

void sio1_init();
void sio1_putc(uint8_t byte);
