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

/* This one is a tough one. Technically, this should return a struct, that's
   using however the older gcc ABI. There's no way to reproduce the ABI
   with modern gcc as far as I know, but it's also likely the rest of
   the returned struct isn't actually used, so we might be lucky here
   in terms of API. As far as ABI is concerned however, inlined assembly
   code will solve the issue. */
int initPadHighLevel(uint32_t padType, uint8_t * buffer, int c, int d);
uint32_t readPadHighLevel();
int initPad(uint8_t * pad1Buffer, size_t pad1BufferSize, uint8_t * pad2Buffer, size_t pad2BufferSize);
int startPad();

extern uint8_t * g_userPadBuffer;
