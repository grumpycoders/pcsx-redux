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
#include "common/psxlibc/handlers.h"
#include "common/psxlibc/stdio.h"
#include "openbios/kernel/events.h"
#include "openbios/kernel/threads.h"

extern struct {
    uint32_t ramsize, unk1, unk2;
} __globals60;

extern struct {
    /* 100 */ struct HandlersStorage * handlersArray;
    /* 104 */ uint32_t handlersArraySize;
    /* 108 */ struct Thread ** blocks;
    /* 10c */ struct Thread * threads;
    /* 110 */ uint32_t xxx_04;
    /* 114 */ uint32_t xxx_05;
    /* 118 */ uint32_t xxx_06;
    /* 11c */ uint32_t xxx_07;
    /* 120 */ struct EventInfo * events;
    /* 124 */ uint32_t eventsSize;
    /* 128 */ uint32_t xxx_0a;
    /* 12c */ uint32_t xxx_0b;
    /* 130 */ uint32_t xxx_0c;
    /* 134 */ uint32_t xxx_0d;
    /* 138 */ uint32_t xxx_0e;
    /* 13c */ uint32_t xxx_0f;
    /* 140 */ struct File * files;
    /* 144 */ uint32_t filesSize;
    /* 148 */ uint32_t xxx_12;
    /* 14c */ uint32_t xxx_13;
    /* 150 */ struct Device * devices;
    /* 154 */ struct Device * devicesEnd;
    /* 158 */ uint32_t xxx_16;
    /* 15c */ uint32_t xxx_17;
    /* 160 */ uint32_t xxx_18;
    /* 164 */ uint32_t xxx_19;
    /* 168 */ uint32_t xxx_1a;
    /* 16c */ uint32_t xxx_1b;
    /* 170 */ uint32_t xxx_1c;
    /* 174 */ uint32_t xxx_1d;
    /* 178 */ uint32_t xxx_1e;
    /* 17c */ uint32_t xxx_1f;
} __globals;
