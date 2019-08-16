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

#include "json.hpp"

#include "core/decode_xa.h"
#include "core/plugins.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "core/r3000a.h"
#include "core/sstate.h"

/*
#define H_SPUirqAddr 0x0da4
#define H_SPUaddr 0x0da6
#define H_SPUdata 0x0da8
#define H_SPUctrl 0x0daa
#define H_SPUstat 0x0dae
#define H_SPUon1 0x0d88
#define H_SPUon2 0x0d8a
#define H_SPUoff1 0x0d8c
#define H_SPUoff2 0x0d8e
*/

namespace PCSX {

class SPUInterface {
  public:
    using json = nlohmann::json;

    void interrupt();
    virtual bool open() = 0;
    virtual long init(void) = 0;
    virtual long shutdown(void) = 0;
    virtual long close(void) = 0;
    virtual uint16_t readRegister(uint32_t) = 0;
    virtual void writeRegister(uint32_t, uint16_t) = 0;
    virtual void playCDDAchannel(int16_t *, int) = 0;
    virtual void playADPCMchannel(xa_decode_t *) = 0;
    virtual void async(uint32_t) = 0;
    virtual void writeDMAMem(uint16_t *, int) = 0;
    virtual void readDMAMem(uint16_t *, int) = 0;
    virtual json getCfg() = 0;
    virtual void setCfg(const json &j) = 0;
    virtual void debug() = 0;
    virtual bool configure() = 0;
    virtual void save(SaveStates::SPU &) = 0;
    virtual void load(const SaveStates::SPU &) = 0;

    bool m_showDebug = false;
    bool m_showCfg = false;


  protected:
    void scheduleInterrupt();
};

}  // namespace PCSX
