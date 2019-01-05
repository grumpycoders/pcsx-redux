/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
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

#include "core/coff.h"
#include "core/plugins.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"

#undef s_addr

typedef struct {
    unsigned char id[8];
    uint32_t text;
    uint32_t data;
    uint32_t pc0;
    uint32_t gp0;
    uint32_t t_addr;
    uint32_t t_size;
    uint32_t d_addr;
    uint32_t d_size;
    uint32_t b_addr;
    uint32_t b_size;
    uint32_t s_addr;
    uint32_t s_size;
    uint32_t SavedSP;
    uint32_t SavedFP;
    uint32_t SavedGP;
    uint32_t SavedRA;
    uint32_t SavedS0;
} EXE_HEADER;

int LoadCdrom();
int LoadCdromFile(const char *filename, EXE_HEADER *head);
int CheckCdrom();
int Load(const char *ExePath);
int LoadLdrFile(const char *LdrPath);

int SaveState(const char *file);
int SaveStateMem(const uint32_t id);
int SaveStateGz(gzFile f, long *gzsize);
int LoadState(const char *file);
int LoadStateMem(const uint32_t id);
int LoadStateGz(gzFile f);
int CheckState(const char *file);

int SendPcsxInfo();
int RecvPcsxInfo();

void CreateRewindState();     // Creates save state and stores it to volatile memory
void RewindState();           // Restores state previously created with CreateRewindState();
void CleanupMemSaveStates();  // Removes all save states stored by memory funcs like CreateRewindState()

void trim(char *str);
uint16_t calcCrc(uint8_t *d, int len);
