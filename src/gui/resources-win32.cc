/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#ifdef _WIN32

#include <stdint.h>
#include <windows.h>

#include "../../resources/resource.h"
#include "gui/resources.h"

static BOOL EnumResNameProc(HMODULE instance, LPCTSTR type, LPTSTR name, LONG_PTR param) {
    HRSRC res = FindResource(instance, name, type);
    if (!res) return TRUE;
    HGLOBAL handle = LoadResource(instance, res);
    if (!handle) return TRUE;
    uint8_t* data = (uint8_t*)LockResource(handle);
    DWORD size = SizeofResource(NULL, res);
    std::function<void(const uint8_t*, uint32_t)>* process;
    process = (std::function<void(const uint8_t*, uint32_t)>*)param;
    (*process)(data, size);
    return TRUE;
}

void PCSX::Resources::loadIcon(std::function<void(const uint8_t*, uint32_t)> process) {
    HMODULE instance = GetModuleHandle(NULL);
    EnumResourceNames(instance, RT_ICON, EnumResNameProc, (LONG_PTR)&process);
}

#endif
