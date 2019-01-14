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

#include <stdint.h>

#include "core/decode_xa.h"

namespace PCSX {

class SPU {
  public:
    // SPU Functions
    long init(void);
    long shutdown(void);
    long close(void);
    //void playSample(unsigned char);
    void writeRegister(unsigned long, unsigned short);
    unsigned short readRegister(unsigned long);
    void writeDMA(unsigned short);
    unsigned short readDMA(void);
    void writeDMAMem(unsigned short*, int);
    void readDMAMem(unsigned short*, int);
    void playADPCMchannel(xa_decode_t*);
    void registerCallback(void (*callback)(void));
    long configure(void);
    long test(void);
    void about(void);

    struct SPUFreeze_t {
        char PluginName[8];
        uint32_t PluginVersion;
        uint32_t Size;
        unsigned char SPUPorts[0x200];
        unsigned char SPURam[0x80000];
        xa_decode_t xa;
        unsigned char* SPUInfo;
    };

    long freeze(uint32_t, SPUFreeze_t*);
    void async(uint32_t);
    void playCDDAchannel(short*, int);
    void registerCDDAVolume(void (*CDDAVcallback)(unsigned short, unsigned short));

  private:
    void LoadStateV5(SPUFreeze_t*);
    void LoadStateUnknown(SPUFreeze_t*);
};

}  // namespace PCSX
