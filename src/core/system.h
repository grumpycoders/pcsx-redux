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

#ifndef __SYSTEM_H__
#define __SYSTEM_H__

#ifdef __cplusplus
extern "C" {
#endif

int SysInit();                                 // Init mem and plugins
void SysReset();                               // Resets mem
void SysPrintf(const char *fmt, ...);          // Printf used by bios syscalls
void SysMessage(const char *fmt, ...);         // Message used to print msg to users
void *SysLoadLibrary(const char *lib);         // Loads Library
void *SysLoadSym(void *lib, const char *sym);  // Loads Symbol from Library
const char *SysLibError();                     // Gets previous error loading sysbols
void SysCloseLibrary(void *lib);               // Closes Library
void SysUpdate();                              // Called on VBlank (to update i.e. pads)
void SysRunGui();                              // Returns to the Gui
void SysClose();                               // Close mem and plugins

#ifdef __cplusplus
}
#endif
#endif
