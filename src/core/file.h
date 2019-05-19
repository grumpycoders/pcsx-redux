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

#include <stdio.h>
#include <stdint.h>

#include "core/psxemulator.h"

namespace PCSX {

class File {
  public:
    void close();
    ssize_t seek(ssize_t pos, int wheel);
    ssize_t tell();
    void flush();
    File(void* data, ssize_t size);
    File(const char* filename);
    ssize_t read(void* dest, ssize_t size);
    ssize_t write(const void* dest, size_t size);
    int getc();
    bool failed();

  private:
    static const uint8_t m_internalBuffer;
    FILE* m_handle = NULL;
    ssize_t m_ptr = 0;
    ssize_t m_size = 0;
    const uint8_t* m_data = NULL;
};

}  // namespace PCSX
