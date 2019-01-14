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
    bool open();
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

//  private:
    // freeze
    void LoadStateV5(SPUFreeze_t*);
    void LoadStateUnknown(SPUFreeze_t*);

    // spu
    void MainThread();
    static int MainThreadTrampoline(void *arg) {
        SPU *that = static_cast<SPU *>(arg);
        that->MainThread();
        return 0;
    }
    void SetupStreams();
    void RemoveStreams();
    void SetupThread();
    void RemoveThread();

    // reverb
    int g_buffer(int iOff); // get_buffer content helper: takes care about wraps
    void s_buffer(int iOff, int iVal);  // set_buffer content helper: takes care about wraps and clipping
    void s_buffer1(int iOff, int iVal);  // set_buffer (+1 sample) content helper: takes care about wraps and clipping
    int MixREVERBLeft(int ns);

// psx buffer / addresses

    unsigned short regArea[10000];
    unsigned short spuMem[256 * 1024];
    unsigned char *spuMemC;
    unsigned char *pSpuIrq = 0;
    unsigned char *pSpuBuffer;
    unsigned char *pMixIrq = 0;
};

}  // namespace PCSX
