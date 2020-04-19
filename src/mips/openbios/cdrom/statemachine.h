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

#include "common/compiler/stdint.h"

int cdromSeekL(uint8_t * msf);
int cdromGetStatus(uint8_t *responsePtr);
int cdromRead(int count, void * buffer, uint32_t mode);
int cdromSetMode(uint32_t mode);
int cdromIOVerifier();
int cdromDMAVerifier();
void cdromIOHandler();
void cdromDMAHandler();
void getLastCDRomError(uint8_t * err1, uint8_t * err2);
int cdromInnerInit();
enum AutoAckType {
    AUTOACK_IO = 0,
    AUTOACK_DMA = 1,
};
int setCDRomIRQAutoAck(enum AutoAckType type, int value);
