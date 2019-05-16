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

#include <stdint.h>

namespace PCSX {

class Bios {
  public:
    Bios() {}
    virtual ~Bios() {}
    static const char *getA0name(uint8_t call);
    static const char *getB0name(uint8_t call);
    static const char *getC0name(uint8_t call);

    virtual void psxBiosInit() = 0;
    virtual void psxBiosShutdown() = 0;
    virtual void psxBiosException() = 0;
    virtual void psxBiosFreeze(int Mode) = 0;

    virtual bool callA0(unsigned index) = 0;
    virtual bool callB0(unsigned index) = 0;
    virtual bool callC0(unsigned index) = 0;

    bool inSoftCall() { return m_hleSoftCall; }

    static Bios *factory();

  protected:
    bool m_hleSoftCall;
};

}  // namespace PCSX
