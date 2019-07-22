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

/*
 * Plugin library callback/access functions.
 */

#include "core/plugins.h"
#include "core/cdriso.h"
#include "core/cdrom.h"
#include "core/gpu.h"
#include "core/pad.h"
#include "core/psxemulator.h"
#include "spu/interface.h"

static char IsoFile[MAXPATHLEN] = "";
static char ExeFile[MAXPATHLEN] = "";
static char AppPath[MAXPATHLEN] = "";  // Application path(== pcsxr.exe directory)
static char LdrFile[MAXPATHLEN] = "";  // bin-load file

#if 0

GPUupdateLace GPU_updateLace;
GPUinit GPU_init;
GPUshutdown GPU_shutdown;
GPUconfigure GPU_configure;
GPUtest GPU_test;
GPUabout GPU_about;
GPUopen GPU_open;
GPUclose GPU_close;
GPUreadStatus GPU_readStatus;
GPUreadData GPU_readData;
GPUreadDataMem GPU_readDataMem;
GPUwriteStatus GPU_writeStatus;
GPUwriteData GPU_writeData;
GPUwriteDataMem GPU_writeDataMem;
GPUdmaChain GPU_dmaChain;
GPUkeypressed GPU_keypressed;
GPUdisplayText GPU_displayText;
GPUmakeSnapshot GPU_makeSnapshot;
GPUtoggleDebug GPU_toggleDebug;
GPUfreeze GPU_freeze;
GPUgetScreenPic GPU_getScreenPic;
GPUshowScreenPic GPU_showScreenPic;
GPUclearDynarec GPU_clearDynarec;
GPUhSync GPU_hSync;
GPUvBlank GPU_vBlank;
GPUvisualVibration GPU_visualVibration;
GPUcursor GPU_cursor;
GPUaddVertex GPU_addVertex;
GPUsetSpeed GPU_setSpeed;
GPUpgxpMemory GPU_pgxpMemory;
GPUpgxpCacheVertex GPU_pgxpCacheVertex;

extern "C" {

#ifdef _WIN32
long softGPUopen(unsigned int texture);
#else
long softGPUopen(unsigned long *disp, const char *CapText, const char *CfgFile);
#endif
void softGPUdisplayText(char *pText);
void softGPUdisplayFlags(uint32_t dwFlags);
void softGPUmakeSnapshot(void);
long softGPUinit();
long softGPUclose();
long softGPUshutdown();
void softGPUcursor(int iPlayer, int x, int y);
void softGPUupdateLace(void);
uint32_t softGPUreadStatus(void);
void softGPUwriteStatus(uint32_t gdata);
void softGPUreadDataMem(uint32_t *pMem, int iSize);
uint32_t softGPUreadData(void);
void softGPUwriteDataMem(uint32_t *pMem, int iSize);
void softGPUwriteData(uint32_t gdata);
void softGPUsetMode(uint32_t gdata);
long softGPUgetMode(void);
long softGPUdmaChain(uint32_t *baseAddrL, uint32_t addr);
long softGPUconfigure(void);
void softGPUabout(void);
long softGPUtest(void);
long softGPUfreeze(uint32_t ulGetFreezeData, GPUFreeze_t *pF);
long softGPUgetScreenPic(unsigned char *pMem);
long softGPUshowScreenPic(unsigned char *pMem);
#ifndef _WIN32
void softGPUkeypressed(int keycode);
#endif
void softGPUhSync(int val);
void softGPUvSync(int val);
void softGPUvisualVibration(uint32_t iSmall, uint32_t iBig);
void softGPUvBlank(int val);
}

#endif

#if 0
SPUconfigure SPU_configure;
SPUabout SPU_about;
SPUinit SPU_init;
SPUshutdown SPU_shutdown;
SPUtest SPU_test;
SPUopen SPU_open;
SPUclose SPU_close;
SPUplaySample SPU_playSample;
SPUwriteRegister SPU_writeRegister;
SPUreadRegister SPU_readRegister;
SPUwriteDMA SPU_writeDMA;
SPUreadDMA SPU_readDMA;
SPUwriteDMAMem SPU_writeDMAMem;
SPUreadDMAMem SPU_readDMAMem;
SPUplayADPCMchannel SPU_playADPCMchannel;
SPUfreeze SPU_freeze;
SPUregisterCallback SPU_registerCallback;
SPUasync SPU_async;
SPUplayCDDAchannel SPU_playCDDAchannel;
#endif

#if 0
PADconfigure PAD1_configure;
PADabout PAD1_about;
PADinit PAD1_init;
PADshutdown PAD1_shutdown;
PADtest PAD1_test;
PADopen PAD1_open;
PADclose PAD1_close;
PADquery PAD1_query;
PADreadPort1 PAD1_readPort1;
PADkeypressed PAD1_keypressed;
PADstartPoll PAD1_startPoll;
PADpoll PCSX::g_emulator.m_pad1->poll;
PADsetSensitive PAD1_setSensitive;
PADregisterVibration PAD1_registerVibration;
PADregisterCursor PAD1_registerCursor;

PADconfigure PAD2_configure;
PADabout PAD2_about;
PADinit PAD2_init;
PADshutdown PAD2_shutdown;
PADtest PAD2_test;
PADopen PAD2_open;
PADclose PAD2_close;
PADquery PAD2_query;
PADreadPort2 PAD2_readPort2;
PADkeypressed PAD2_keypressed;
PADstartPoll PAD2_startPoll;
PADpoll PCSX::g_emulator.m_pad2->poll;
PADsetSensitive PAD2_setSensitive;
PADregisterVibration PAD2_registerVibration;
PADregisterCursor PAD2_registerCursor;
#endif

NETinit NET_init;
NETshutdown NET_shutdown;
NETopen NET_open;
NETclose NET_close;
NETtest NET_test;
NETconfigure NET_configure;
NETabout NET_about;
NETpause NET_pause;
NETresume NET_resume;
NETqueryPlayer NET_queryPlayer;
NETsendData NET_sendData;
NETrecvData NET_recvData;
NETsendPadData NET_sendPadData;
NETrecvPadData NET_recvPadData;
NETsetInfo NET_setInfo;
NETkeypressed NET_keypressed;

#ifdef ENABLE_SIO1API

SIO1init SIO1_init;
SIO1shutdown SIO1_shutdown;
SIO1open SIO1_open;
SIO1close SIO1_close;
SIO1test SIO1_test;
SIO1configure SIO1_configure;
SIO1about SIO1_about;
SIO1pause SIO1_pause;
SIO1resume SIO1_resume;
SIO1keypressed SIO1_keypressed;
SIO1writeData8 SIO1_writeData8;
SIO1writeData16 SIO1_writeData16;
SIO1writeData32 SIO1_writeData32;
SIO1writeStat16 SIO1_writeStat16;
SIO1writeStat32 SIO1_writeStat32;
SIO1writeMode16 SIO1_writeMode16;
SIO1writeMode32 SIO1_writeMode32;
SIO1writeCtrl16 SIO1_writeCtrl16;
SIO1writeCtrl32 SIO1_writeCtrl32;
SIO1writeBaud16 SIO1_writeBaud16;
SIO1writeBaud32 SIO1_writeBaud32;
SIO1readData8 SIO1_readData8;
SIO1readData16 SIO1_readData16;
SIO1readData32 SIO1_readData32;
SIO1readStat16 SIO1_readStat16;
SIO1readStat32 SIO1_readStat32;
SIO1readMode16 SIO1_readMode16;
SIO1readMode32 SIO1_readMode32;
SIO1readCtrl16 SIO1_readCtrl16;
SIO1readCtrl32 SIO1_readCtrl32;
SIO1readBaud16 SIO1_readBaud16;
SIO1readBaud32 SIO1_readBaud32;
SIO1update SIO1_update;
SIO1registerCallback SIO1_registerCallback;

#endif

static const char *err;

#define CheckErr(func)                                                     \
    {                                                                      \
        err = SysLibError();                                               \
        if (err != NULL) {                                                 \
            PCSX::g_system->message(_("Error loading %s: %s"), func, err); \
            return -1;                                                     \
        }                                                                  \
    }

#define LoadSym(dest, src, name, checkerr) \
    {                                      \
        dest = (src)SysLoadSym(drv, name); \
        if (checkerr) {                    \
            CheckErr(name);                \
        } else                             \
            SysLibError();                 \
    }

#if 0
#define LoadGpuSym1(dest, name) LoadSym(GPU_##dest, GPU##dest, name, true);

#define LoadGpuSym0(dest, name)                  \
    LoadSym(GPU_##dest, GPU##dest, name, false); \
    if (GPU_##dest == NULL) GPU_##dest = (GPU##dest)GPU__##dest;

#define LoadGpuSymN(dest, name) LoadSym(GPU_##dest, GPU##dest, name, false);
#endif

static int LoadGPUplugin() {
#if 0
    LoadGpuSym1(init, "GPUinit");
    LoadGpuSym1(shutdown, "GPUshutdown");
    LoadGpuSym1(open, "GPUopen");
    LoadGpuSym1(close, "GPUclose");
    LoadGpuSym1(readData, "GPUreadData");
    LoadGpuSym1(readDataMem, "GPUreadDataMem");
    LoadGpuSym1(readStatus, "GPUreadStatus");
    LoadGpuSym1(writeData, "GPUwriteData");
    LoadGpuSym1(writeDataMem, "GPUwriteDataMem");
    LoadGpuSym1(writeStatus, "GPUwriteStatus");
    LoadGpuSym1(dmaChain, "GPUdmaChain");
    LoadGpuSym1(updateLace, "GPUupdateLace");
    LoadGpuSym0(keypressed, "GPUkeypressed");
    LoadGpuSym0(displayText, "GPUdisplayText");
    LoadGpuSym0(makeSnapshot, "GPUmakeSnapshot");
    LoadGpuSym0(toggleDebug, "GPUtoggleDebug");
    LoadGpuSym1(freeze, "GPUfreeze");
    LoadGpuSym0(getScreenPic, "GPUgetScreenPic");
    LoadGpuSym0(showScreenPic, "GPUshowScreenPic");
    LoadGpuSym0(clearDynarec, "GPUclearDynarec");
    LoadGpuSym0(hSync, "GPUhSync");
    LoadGpuSym0(vBlank, "GPUvBlank");
    LoadGpuSym0(visualVibration, "GPUvisualVibration");
    LoadGpuSym0(cursor, "GPUcursor");
    LoadGpuSym0(addVertex, "GPUaddVertex");
    LoadGpuSym0(setSpeed, "GPUsetSpeed");
    LoadGpuSym0(pgxpMemory, "GPUpgxpMemory");
    LoadGpuSym0(pgxpCacheVertex, "GPUpgxpCacheVertex");
    LoadGpuSym0(configure, "GPUconfigure");
    LoadGpuSym0(test, "GPUtest");
    LoadGpuSym0(about, "GPUabout");
#endif

#if 0

#define LoadGpuSymD(s, x) GPU_##s = GPU__##s;
#define LoadGpuSym0(s, x) GPU_##s = softGPU##s
#define LoadGpuSym1(s, x) GPU_##s = softGPU##s

    LoadGpuSym1(init, "GPUinit");
    LoadGpuSym1(shutdown, "GPUshutdown");
    LoadGpuSym1(open, "GPUopen");
    LoadGpuSym1(close, "GPUclose");
    LoadGpuSym1(readData, "GPUreadData");
    LoadGpuSym1(readDataMem, "GPUreadDataMem");
    LoadGpuSym1(readStatus, "GPUreadStatus");
    LoadGpuSym1(writeData, "GPUwriteData");
    LoadGpuSym1(writeDataMem, "GPUwriteDataMem");
    LoadGpuSym1(writeStatus, "GPUwriteStatus");
    LoadGpuSym1(dmaChain, "GPUdmaChain");
    LoadGpuSym1(updateLace, "GPUupdateLace");
    LoadGpuSymD(keypressed, "GPUkeypressed");
    LoadGpuSym0(displayText, "GPUdisplayText");
    LoadGpuSym0(makeSnapshot, "GPUmakeSnapshot");
    LoadGpuSymD(toggleDebug, "GPUtoggleDebug");
    LoadGpuSym1(freeze, "GPUfreeze");
    LoadGpuSym0(getScreenPic, "GPUgetScreenPic");
    LoadGpuSym0(showScreenPic, "GPUshowScreenPic");
    LoadGpuSymD(clearDynarec, "GPUclearDynarec");
    LoadGpuSymD(hSync, "GPUhSync");
    LoadGpuSymD(vBlank, "GPUvBlank");
    LoadGpuSym0(visualVibration, "GPUvisualVibration");
    LoadGpuSym0(cursor, "GPUcursor");
    LoadGpuSymD(addVertex, "GPUaddVertex");
    LoadGpuSymD(setSpeed, "GPUsetSpeed");
    LoadGpuSymD(pgxpMemory, "GPUpgxpMemory");
    LoadGpuSymD(pgxpCacheVertex, "GPUpgxpCacheVertex");
    LoadGpuSym0(configure, "GPUconfigure");
    LoadGpuSym0(test, "GPUtest");
    LoadGpuSym0(about, "GPUabout");

#endif

    return 0;
}

#include <stdlib.h>
#include <string.h>

#include "decode_xa.h"
#include "psxemulator.h"

#if 0
static unsigned char s_buf[256];
unsigned char stdpar[10] = {0x00, 0x41, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
unsigned char mousepar[8] = {0x00, 0x12, 0x5a, 0xff, 0xff, 0xff, 0xff};
unsigned char analogpar[9] = {0x00, 0xff, 0x5a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static int m_maxBufferIndex, bufc;

PadDataS padd1, padd2;

unsigned char _PADstartPoll(PadDataS *pad) {
    bufc = 0;

    switch (pad->controllerType) {
        case PSE_PAD_TYPE_MOUSE:
            mousepar[3] = pad->buttonStatus & 0xff;
            mousepar[4] = pad->buttonStatus >> 8;
            mousepar[5] = pad->moveX;
            mousepar[6] = pad->moveY;

            memcpy(s_buf, mousepar, 7);
            m_maxBufferIndex = 6;
            break;
        case PSE_PAD_TYPE_NEGCON:  // npc101/npc104(slph00001/slph00069)
            analogpar[1] = 0x23;
            analogpar[3] = pad->buttonStatus & 0xff;
            analogpar[4] = pad->buttonStatus >> 8;
            analogpar[5] = pad->rightJoyX;
            analogpar[6] = pad->rightJoyY;
            analogpar[7] = pad->leftJoyX;
            analogpar[8] = pad->leftJoyY;

            memcpy(s_buf, analogpar, 9);
            m_maxBufferIndex = 8;
            break;
        case PSE_PAD_TYPE_ANALOGPAD:  // scph1150
            analogpar[1] = 0x73;
            analogpar[3] = pad->buttonStatus & 0xff;
            analogpar[4] = pad->buttonStatus >> 8;
            analogpar[5] = pad->rightJoyX;
            analogpar[6] = pad->rightJoyY;
            analogpar[7] = pad->leftJoyX;
            analogpar[8] = pad->leftJoyY;

            memcpy(s_buf, analogpar, 9);
            m_maxBufferIndex = 8;
            break;
        case PSE_PAD_TYPE_ANALOGJOY:  // scph1110
            analogpar[1] = 0x53;
            analogpar[3] = pad->buttonStatus & 0xff;
            analogpar[4] = pad->buttonStatus >> 8;
            analogpar[5] = pad->rightJoyX;
            analogpar[6] = pad->rightJoyY;
            analogpar[7] = pad->leftJoyX;
            analogpar[8] = pad->leftJoyY;

            memcpy(s_buf, analogpar, 9);
            m_maxBufferIndex = 8;
            break;
        case PSE_PAD_TYPE_STANDARD:
        default:
            stdpar[3] = pad->buttonStatus & 0xff;
            stdpar[4] = pad->buttonStatus >> 8;

            memcpy(s_buf, stdpar, 5);
            m_maxBufferIndex = 4;
    }

    return s_buf[bufc++];
}

unsigned char _PADpoll(unsigned char value) {
    if (bufc > m_maxBufferIndex) return 0;
    return s_buf[bufc++];
}

unsigned char PAD1__startPoll(int pad) {
    PadDataS padd;

    PAD1_readPort1(&padd);

    return _PADstartPoll(&padd);
}

unsigned char PAD1__poll(unsigned char value) { return _PADpoll(value); }

long PAD1__configure(void) { return 0; }
void PAD1__about(void) {}
long PAD1__test(void) { return 0; }
long PAD1__query(void) { return 3; }
long PAD1__keypressed() { return 0; }
void PAD1__registerVibration(void (*callback)(uint32_t, uint32_t)) {}
void PAD1__registerCursor(void (*callback)(int, int, int)) {}

#define LoadPad1Sym1(dest, name) LoadSym(PAD1_##dest, PAD##dest, name, true);

#define LoadPad1SymN(dest, name) LoadSym(PAD1_##dest, PAD##dest, name, false);

#define LoadPad1Sym0(dest, name)                  \
    LoadSym(PAD1_##dest, PAD##dest, name, false); \
    if (PAD1_##dest == NULL) PAD1_##dest = (PAD##dest)PAD1__##dest;

long nullPAD_init(long flags) { return 0; }
long nullPAD_shutdown() { return 0; }
long nullPAD_open(HWND x) { return 0; }
long nullPAD_close() { return 0; }
long simplePAD_readPort(PadDataS *data) {
    memset(data, 0, sizeof(PadDataS));
    data->buttonStatus = pad1.getButtons();
    return 0;
}
long nullPAD_readPort(PadDataS *data) {
    memset(data, 0, sizeof(PadDataS));
    data->buttonStatus = 0xffff;
    return 0;
}

static int LoadPAD1plugin() {
#if 0
    LoadPad1Sym1(init, "PADinit");
    LoadPad1Sym1(shutdown, "PADshutdown");
    LoadPad1Sym1(open, "PADopen");
    LoadPad1Sym1(close, "PADclose");
    LoadPad1Sym0(query, "PADquery");
    LoadPad1Sym1(readPort1, "PADreadPort1");
    LoadPad1Sym0(configure, "PADconfigure");
    LoadPad1Sym0(test, "PADtest");
    LoadPad1Sym0(about, "PADabout");
    LoadPad1Sym0(keypressed, "PADkeypressed");
    LoadPad1Sym0(startPoll, "PADstartPoll");
    LoadPad1Sym0(poll, "PADpoll");
    LoadPad1SymN(setSensitive, "PADsetSensitive");
    LoadPad1Sym0(registerVibration, "PADregisterVibration");
    LoadPad1Sym0(registerCursor, "PADregisterCursor");
#endif

    PAD1_init = nullPAD_init;
    PAD1_shutdown = nullPAD_shutdown;
    PAD1_open = nullPAD_open;
    PAD1_close = nullPAD_close;
    PAD1_readPort1 = simplePAD_readPort;
    PAD1_query = PAD1__query;
    PAD1_configure = PAD1__configure;
    PAD1_test = PAD1__test;
    PAD1_about = PAD1__about;
    PAD1_keypressed = PAD1__keypressed;
    PAD1_startPoll = PAD1__startPoll;
    PCSX::g_emulator.m_pad1->poll = PAD1__poll;
    PAD1_registerVibration = PAD1__registerVibration;
    PAD1_registerCursor = PAD1__registerCursor;

    return 0;
}

unsigned char PAD2__startPoll(int pad) {
    PadDataS padd;

    PAD2_readPort2(&padd);

    return _PADstartPoll(&padd);
}

unsigned char PAD2__poll(unsigned char value) { return _PADpoll(value); }

long PAD2__configure(void) { return 0; }
void PAD2__about(void) {}
long PAD2__test(void) { return 0; }
long PAD2__query(void) { return PSE_PAD_USE_PORT1 | PSE_PAD_USE_PORT2; }
long PAD2__keypressed() { return 0; }
void PAD2__registerVibration(void (*callback)(uint32_t, uint32_t)) {}
void PAD2__registerCursor(void (*callback)(int, int, int)) {}

#define LoadPad2Sym1(dest, name) LoadSym(PAD2_##dest, PAD##dest, name, true);

#define LoadPad2Sym0(dest, name)                  \
    LoadSym(PAD2_##dest, PAD##dest, name, false); \
    if (PAD2_##dest == NULL) PAD2_##dest = (PAD##dest)PAD2__##dest;

#define LoadPad2SymN(dest, name) LoadSym(PAD2_##dest, PAD##dest, name, false);

static int LoadPAD2plugin() {
#if 0
    LoadPad2Sym1(init, "PADinit");
    LoadPad2Sym1(shutdown, "PADshutdown");
    LoadPad2Sym1(open, "PADopen");
    LoadPad2Sym1(close, "PADclose");
    LoadPad2Sym0(query, "PADquery");
    LoadPad2Sym1(readPort2, "PADreadPort2");
    LoadPad2Sym0(configure, "PADconfigure");
    LoadPad2Sym0(test, "PADtest");
    LoadPad2Sym0(about, "PADabout");
    LoadPad2Sym0(keypressed, "PADkeypressed");
    LoadPad2Sym0(startPoll, "PADstartPoll");
    LoadPad2Sym0(poll, "PADpoll");
    LoadPad2SymN(setSensitive, "PADsetSensitive");
    LoadPad2Sym0(registerVibration, "PADregisterVibration");
    LoadPad2Sym0(registerCursor, "PADregisterCursor");
#endif

    PAD2_init = nullPAD_init;
    PAD2_shutdown = nullPAD_shutdown;
    PAD2_open = nullPAD_open;
    PAD2_close = nullPAD_close;
    PAD2_readPort2 = nullPAD_readPort;
    PAD2_query = PAD2__query;
    PAD2_configure = PAD2__configure;
    PAD2_test = PAD2__test;
    PAD2_about = PAD2__about;
    PAD2_keypressed = PAD2__keypressed;
    PAD2_startPoll = PAD2__startPoll;
    PCSX::g_emulator.m_pad2->poll = PAD2__poll;
    PAD2_registerVibration = PAD2__registerVibration;
    PAD2_registerCursor = PAD2__registerCursor;

    return 0;
}
#endif

#ifdef ENABLE_SIO1API

long SIO1__init(void) { return 0; }
long SIO1__shutdown(void) { return 0; }
long SIO1__open(void) { return 0; }
long SIO1__close(void) { return 0; }
long SIO1__configure(void) { return 0; }
long SIO1__test(void) { return 0; }
void SIO1__about(void) {}
void SIO1__pause(void) {}
void SIO1__resume(void) {}
long SIO1__keypressed(int key) { return 0; }
void SIO1__writeData8(uint8_t val) {}
void SIO1__writeData16(uint16_t val) {}
void SIO1__writeData32(uint32_t val) {}
void SIO1__writeStat16(uint16_t val) {}
void SIO1__writeStat32(uint32_t val) {}
void SIO1__writeMode16(uint16_t val) {}
void SIO1__writeMode32(uint32_t val) {}
void SIO1__writeCtrl16(uint16_t val) {}
void SIO1__writeCtrl32(uint32_t val) {}
void SIO1__writeBaud16(uint16_t val) {}
void SIO1__writeBaud32(uint32_t val) {}
uint8_t SIO1__readData8(void) { return 0; }
uint16_t SIO1__readData16(void) { return 0; }
uint32_t SIO1__readData32(void) { return 0; }
uint16_t SIO1__readStat16(void) { return 0; }
uint32_t SIO1__readStat32(void) { return 0; }
uint16_t SIO1__readMode16(void) { return 0; }
uint32_t SIO1__readMode32(void) { return 0; }
uint16_t SIO1__readCtrl16(void) { return 0; }
uint32_t SIO1__readCtrl32(void) { return 0; }
uint16_t SIO1__readBaud16(void) { return 0; }
uint32_t SIO1__readBaud32(void) { return 0; }
void SIO1__update(uint32_t t){};
void SIO1__registerCallback(void (*callback)(void)){};

#define LoadSio1Sym1(dest, name) LoadSym(SIO1_##dest, SIO1##dest, name, true);

#define LoadSio1SymN(dest, name) LoadSym(SIO1_##dest, SIO1##dest, name, false);

#define LoadSio1Sym0(dest, name)                   \
    LoadSym(SIO1_##dest, SIO1##dest, name, false); \
    if (SIO1_##dest == NULL) SIO1_##dest = (SIO1##dest)SIO1__##dest;

static int LoadSIO1plugin(const char *SIO1dll) {
    LoadSio1Sym0(init, "SIO1init");
    LoadSio1Sym0(shutdown, "SIO1shutdown");
    LoadSio1Sym0(open, "SIO1open");
    LoadSio1Sym0(close, "SIO1close");
    LoadSio1Sym0(pause, "SIO1pause");
    LoadSio1Sym0(resume, "SIO1resume");
    LoadSio1Sym0(keypressed, "SIO1keypressed");
    LoadSio1Sym0(configure, "SIO1configure");
    LoadSio1Sym0(test, "SIO1test");
    LoadSio1Sym0(about, "SIO1about");
    LoadSio1Sym0(writeData8, "SIO1writeData8");
    LoadSio1Sym0(writeData16, "SIO1writeData16");
    LoadSio1Sym0(writeData32, "SIO1writeData32");
    LoadSio1Sym0(writeStatus16, "SIO1writeStat16");
    LoadSio1Sym0(writeStat32, "SIO1writeStat32");
    LoadSio1Sym0(writeMode16, "SIO1writeMode16");
    LoadSio1Sym0(writeMode32, "SIO1writeMode32");
    LoadSio1Sym0(writeCtrl16, "SIO1writeCtrl16");
    LoadSio1Sym0(writeCtrl32, "SIO1writeCtrl32");
    LoadSio1Sym0(writeBaud16, "SIO1writeBaud16");
    LoadSio1Sym0(writeBaud32, "SIO1writeBaud32");
    LoadSio1Sym0(readData8, "SIO1readData8");
    LoadSio1Sym0(readData16, "SIO1readData16");
    LoadSio1Sym0(readData32, "SIO1readData32");
    LoadSio1Sym0(readStatus16, "SIO1readStat16");
    LoadSio1Sym0(readStat32, "SIO1readStat32");
    LoadSio1Sym0(readMode16, "SIO1readMode16");
    LoadSio1Sym0(readMode32, "SIO1readMode32");
    LoadSio1Sym0(readCtrl16, "SIO1readCtrl16");
    LoadSio1Sym0(readCtrl32, "SIO1readCtrl32");
    LoadSio1Sym0(readBaud16, "SIO1readBaud16");
    LoadSio1Sym0(readBaud32, "SIO1readBaud32");
    LoadSio1Sym0(update, "SIO1update");
    LoadSio1Sym0(registerCallback, "SIO1registerCallback");

    return 0;
}

#endif

void clearDynarec(void) { PCSX::g_emulator.m_psxCpu->Reset(); }

int LoadPlugins() {
    long ret;

    ReleasePlugins();

    if (LoadGPUplugin() == -1) return -1;

#ifdef ENABLE_SIO1API
    if (LoadSIO1plugin() == -1) return -1;
#endif

    PCSX::g_emulator.m_cdrom->m_iso.init();
    ret = PCSX::g_emulator.m_gpu->init();
    if (ret < 0) {
        PCSX::g_system->message(_("Error initializing GPU plugin: %d"), ret);
        return -1;
    }
    ret = PCSX::g_emulator.m_spu->init();
    if (ret < 0) {
        PCSX::g_system->message(_("Error initializing SPU plugin: %d"), ret);
        return -1;
    }

#ifdef ENABLE_SIO1API
    ret = SIO1_init();
    if (ret < 0) {
        PCSX::g_system->message(_("Error initializing SIO1 plugin: %d"), ret);
        return -1;
    }
#endif

    PCSX::g_system->printf("%s", _("Plugins loaded.\n"));
    return 0;
}

void ReleasePlugins() {
    PCSX::g_emulator.m_cdrom->m_iso.shutdown();
    PCSX::g_emulator.m_gpu->shutdown();
    PCSX::g_emulator.m_spu->shutdown();

#ifdef ENABLE_SIO1API
    SIO1_shutdown();
#endif
}

void SetIsoFile(const char *filename) {
    if (filename == NULL) {
        IsoFile[0] = '\0';
        return;
    }
    strncpy(IsoFile, filename, MAXPATHLEN);
}

void SetExeFile(const char *filename) {
    if (filename == NULL) {
        ExeFile[0] = '\0';
        return;
    }
    strncpy(ExeFile, filename, MAXPATHLEN);
}

// Set pcsxr.exe directory. This is not contain filename(and ext)).
void SetAppPath(const char *apppath) {
    if (apppath == NULL) {
        AppPath[0] = '\0';
        return;
    }
    strncpy(AppPath, apppath, MAXPATHLEN);
}

void SetLdrFile(const char *ldrfile) {
    if (ldrfile == NULL) {
        LdrFile[0] = '\0';
        return;
    }
    strncpy(LdrFile, ldrfile, MAXPATHLEN);
}

const char *GetIsoFile(void) { return IsoFile; }

const char *GetExeFile(void) { return ExeFile; }

const char *GetAppPath(void) { return AppPath; }

const char *GetLdrFile(void) { return LdrFile; }
