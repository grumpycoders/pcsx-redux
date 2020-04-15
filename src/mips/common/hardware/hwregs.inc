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

.set SBUS_DEV0_ADDR,    0x1f801000
.set SBUS_DEV8_ADDR,    0x1f801004

.set SBUS_DEV0_CTRL,    0x1f801008
.set SBUS_DEV1_CTRL,    0x1f80100C
.set SBUS_DEV2_CTRL,    0x1f801010
.set SBUS_DEV4_CTRL,    0x1f801014
.set SBUS_DEV5_CTRL,    0x1f801018
.set SBUS_DEV8_CTRL,    0x1f80101C

.set SBUS_COM_CTRL,     0x1f801020

.set RAM_SIZE,          0x1f801060

.set BIU_CONFIG,        0xfffe0130
