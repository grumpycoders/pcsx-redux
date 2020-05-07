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
#include "common/psxlibc/direntry.h"
#include "common/psxlibc/stdio.h"

extern char g_cdromCWD[128];

int cdromReadPathTable();
int dev_cd_open(struct File * file, char * filename);
int dev_cd_read(struct File * file,char * buffer, int size);
struct DirEntry * dev_cd_firstfile(struct File * file, const char * filename, struct DirEntry * entry);
struct DirEntry * dev_cd_nextfile(struct File * file, struct DirEntry * entry);
int dev_cd_chdir(struct File * file, char * name);
