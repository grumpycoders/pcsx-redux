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

#ifndef __PLUGINS_H__
#define __PLUGINS_H__

#include "core/psxemulator.h"

#ifndef _WIN32

typedef void* HWND;

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "core/decode_xa.h"
#include "core/psemu_plugin_defs.h"
#include "core/spu.h"

#endif

extern "C" {

typedef long (*GPUopen)(unsigned int texture);
long SPUopen(HWND);
typedef long (*PADopen)(HWND);
typedef long (*NETopen)(HWND);
typedef long (*SIO1open)(HWND);
}

int LoadPlugins();
void ReleasePlugins();

typedef unsigned long (*PSEgetLibType)(void);
typedef unsigned long (*PSEgetLibVersion)(void);
typedef char* (*PSEgetLibName)(void);

#if 0
// GPU Functions
typedef long(* GPUinit)(void);
typedef long(* GPUshutdown)(void);
typedef long(* GPUclose)(void);
typedef void(* GPUwriteStatus)(uint32_t);
typedef void(* GPUwriteData)(uint32_t);
typedef void(* GPUwriteDataMem)(uint32_t*, int);
typedef uint32_t(* GPUreadStatus)(void);
typedef uint32_t(* GPUreadData)(void);
typedef void(* GPUreadDataMem)(uint32_t*, int);
typedef long(* GPUdmaChain)(uint32_t*, uint32_t);
typedef void(* GPUupdateLace)(void);
typedef long(* GPUconfigure)(void);
typedef long(* GPUtest)(void);
typedef void(* GPUabout)(void);
typedef void(* GPUmakeSnapshot)(void);
typedef void(* GPUtoggleDebug)(void);
typedef void(* GPUkeypressed)(int);
typedef void(* GPUdisplayText)(char*);
typedef long(* GPUfreeze)(uint32_t, GPUFreeze_t*);
typedef long(* GPUgetScreenPic)(unsigned char*);
typedef long(* GPUshowScreenPic)(unsigned char*);
typedef void(* GPUclearDynarec)(void(* callback)(void));
typedef void(* GPUhSync)(int);
typedef void(* GPUvBlank)(int);
typedef void(* GPUvisualVibration)(uint32_t, uint32_t);
typedef void(* GPUcursor)(int, int, int);
typedef void(* GPUaddVertex)(short, short, int64_t, int64_t, int64_t);
typedef void(* GPUsetSpeed)(float);  // 1.0 = natural speed
typedef void(* GPUpgxpMemory)(unsigned int, unsigned char*);
typedef void(* GPUpgxpCacheVertex)(short sx, short sy, const unsigned char* _pVertex);
#endif

#if 0
// GPU function pointers
extern GPUupdateLace GPU_updateLace;
extern GPUinit GPU_init;
extern GPUshutdown GPU_shutdown;
extern GPUconfigure GPU_configure;
extern GPUtest GPU_test;
extern GPUabout GPU_about;
extern GPUopen GPU_open;
extern GPUclose GPU_close;
extern GPUreadStatus GPU_readStatus;
extern GPUreadData GPU_readData;
extern GPUreadDataMem GPU_readDataMem;
extern GPUwriteStatus GPU_writeStatus;
extern GPUwriteData GPU_writeData;
extern GPUwriteDataMem GPU_writeDataMem;
extern GPUdmaChain GPU_dmaChain;
extern GPUkeypressed GPU_keypressed;
extern GPUdisplayText GPU_displayText;
extern GPUmakeSnapshot GPU_makeSnapshot;
extern GPUtoggleDebug GPU_toggleDebug;
extern GPUfreeze GPU_freeze;
extern GPUgetScreenPic GPU_getScreenPic;
extern GPUshowScreenPic GPU_showScreenPic;
extern GPUclearDynarec GPU_clearDynarec;
extern GPUhSync GPU_hSync;
extern GPUvBlank GPU_vBlank;
extern GPUvisualVibration GPU_visualVibration;
extern GPUcursor GPU_cursor;
extern GPUaddVertex GPU_addVertex;
extern GPUsetSpeed GPU_setSpeed;
extern GPUpgxpMemory GPU_pgxpMemory;
extern GPUpgxpCacheVertex GPU_pgxpCacheVertex;
#endif

struct CdrStat {
    uint32_t Type;
    uint32_t Status;
    unsigned char Time[3];
};
struct SubQ {
    char res0[12];
    unsigned char ControlAndADR;
    unsigned char TrackNumber;
    unsigned char IndexNumber;
    unsigned char TrackRelativeAddress[3];
    unsigned char Filler;
    unsigned char AbsoluteAddress[3];
    unsigned char CRC[2];
    char res1[72];
};

// PAD Functions
#if 0
struct PadDataS;
typedef long (*PADconfigure)(void);
typedef void (*PADabout)(void);
typedef long (*PADinit)(long);
typedef long (*PADshutdown)(void);
typedef long (*PADtest)(void);
typedef long (*PADclose)(void);
typedef long (*PADquery)(void);
typedef long (*PADreadPort1)(PadDataS*);
typedef long (*PADreadPort2)(PadDataS*);
typedef long (*PADkeypressed)(void);
typedef unsigned char (*PADstartPoll)(int);
typedef unsigned char (*PADpoll)(unsigned char);
typedef void (*PADsetSensitive)(int);
typedef void (*PADregisterVibration)(void (*callback)(uint32_t, uint32_t));
typedef void (*PADregisterCursor)(void (*callback)(int, int, int));

// PAD function pointers
extern PADconfigure PAD1_configure;
extern PADabout PAD1_about;
extern PADinit PAD1_init;
extern PADshutdown PAD1_shutdown;
extern PADtest PAD1_test;
extern PADopen PAD1_open;
extern PADclose PAD1_close;
extern PADquery PAD1_query;
extern PADreadPort1 PAD1_readPort1;
extern PADkeypressed PAD1_keypressed;
extern PADstartPoll PAD1_startPoll;
extern PADpoll PCSX::g_emulator->m_pad1->poll;
extern PADsetSensitive PAD1_setSensitive;
extern PADregisterVibration PAD1_registerVibration;
extern PADregisterCursor PAD1_registerCursor;
extern PADconfigure PAD2_configure;
extern PADabout PAD2_about;
extern PADinit PAD2_init;
extern PADshutdown PAD2_shutdown;
extern PADtest PAD2_test;
extern PADopen PAD2_open;
extern PADclose PAD2_close;
extern PADquery PAD2_query;
extern PADreadPort2 PAD2_readPort2;
extern PADkeypressed PAD2_keypressed;
extern PADstartPoll PAD2_startPoll;
extern PADpoll PCSX::g_emulator->m_pad2->poll;
extern PADsetSensitive PAD2_setSensitive;
extern PADregisterVibration PAD2_registerVibration;
extern PADregisterCursor PAD2_registerCursor;
#endif

// NET Functions
typedef long (*NETinit)(void);
typedef long (*NETshutdown)(void);
typedef long (*NETclose)(void);
typedef long (*NETconfigure)(void);
typedef long (*NETtest)(void);
typedef void (*NETabout)(void);
typedef void (*NETpause)(void);
typedef void (*NETresume)(void);
typedef long (*NETqueryPlayer)(void);
typedef long (*NETsendData)(void*, int, int);
typedef long (*NETrecvData)(void*, int, int);
typedef long (*NETsendPadData)(void*, int);
typedef long (*NETrecvPadData)(void*, int);

typedef struct {
    char EmuName[32];
    char CdromID[9];  // ie. 'SCPH12345', no \0 trailing character
    char CdromLabel[11];
    void* psxMem;
    //    GPUshowScreenPic GPU_showScreenPic;
    //    GPUdisplayText GPU_displayText;
    //    PADsetSensitive PAD_setSensitive;
    char GPUpath[256];  // paths must be absolute
    char SPUpath[256];
    char CDRpath[256];
    char MCD1path[256];
    char MCD2path[256];
    char BIOSpath[256];  // 'HLE' for internal bios
    char Unused[1024];
} netInfo;

typedef long (*NETsetInfo)(netInfo*);
typedef long (*NETkeypressed)(int);

// NET function pointers
extern NETinit NET_init;
extern NETshutdown NET_shutdown;
extern NETopen NET_open;
extern NETclose NET_close;
extern NETtest NET_test;
extern NETconfigure NET_configure;
extern NETabout NET_about;
extern NETpause NET_pause;
extern NETresume NET_resume;
extern NETqueryPlayer NET_queryPlayer;
extern NETsendData NET_sendData;
extern NETrecvData NET_recvData;
extern NETsendPadData NET_sendPadData;
extern NETrecvPadData NET_recvPadData;
extern NETsetInfo NET_setInfo;
extern NETkeypressed NET_keypressed;

#ifdef ENABLE_SIO1API

// SIO1 Functions (link cable)
typedef long (*SIO1init)(void);
typedef long (*SIO1shutdown)(void);
typedef long (*SIO1close)(void);
typedef long (*SIO1configure)(void);
typedef long (*SIO1test)(void);
typedef void (*SIO1about)(void);
typedef void (*SIO1pause)(void);
typedef void (*SIO1resume)(void);
typedef long (*SIO1keypressed)(int);
typedef void (*SIO1writeData8)(uint8_t);
typedef void (*SIO1writeData16)(uint16_t);
typedef void (*SIO1writeData32)(uint32_t);
typedef void (*SIO1writeStat16)(uint16_t);
typedef void (*SIO1writeStat32)(uint32_t);
typedef void (*SIO1writeMode16)(uint16_t);
typedef void (*SIO1writeMode32)(uint32_t);
typedef void (*SIO1writeCtrl16)(uint16_t);
typedef void (*SIO1writeCtrl32)(uint32_t);
typedef void (*SIO1writeBaud16)(uint16_t);
typedef void (*SIO1writeBaud32)(uint32_t);
typedef uint8_t (*SIO1readData8)(void);
typedef uint16_t (*SIO1readData16)(void);
typedef uint32_t (*SIO1readData32)(void);
typedef uint16_t (*SIO1readStat16)(void);
typedef uint32_t (*SIO1readStat32)(void);
typedef uint16_t (*SIO1readMode16)(void);
typedef uint32_t (*SIO1readMode32)(void);
typedef uint16_t (*SIO1readCtrl16)(void);
typedef uint32_t (*SIO1readCtrl32)(void);
typedef uint16_t (*SIO1readBaud16)(void);
typedef uint32_t (*SIO1readBaud32)(void);
typedef void (*SIO1update)(uint32_t);
typedef void (*SIO1registerCallback)(void (*callback)(void));

// SIO1 function pointers
extern SIO1init SIO1_init;
extern SIO1shutdown SIO1_shutdown;
extern SIO1open SIO1_open;
extern SIO1close SIO1_close;
extern SIO1test SIO1_test;
extern SIO1configure SIO1_configure;
extern SIO1about SIO1_about;
extern SIO1pause SIO1_pause;
extern SIO1resume SIO1_resume;
extern SIO1keypressed SIO1_keypressed;
extern SIO1writeData8 SIO1_writeData8;
extern SIO1writeData16 SIO1_writeData16;
extern SIO1writeData32 SIO1_writeData32;
extern SIO1writeStat16 SIO1_writeStat16;
extern SIO1writeStat32 SIO1_writeStat32;
extern SIO1writeMode16 SIO1_writeMode16;
extern SIO1writeMode32 SIO1_writeMode32;
extern SIO1writeCtrl16 SIO1_writeCtrl16;
extern SIO1writeCtrl32 SIO1_writeCtrl32;
extern SIO1writeBaud16 SIO1_writeBaud16;
extern SIO1writeBaud32 SIO1_writeBaud32;
extern SIO1readData8 SIO1_readData8;
extern SIO1readData16 SIO1_readData16;
extern SIO1readData32 SIO1_readData32;
extern SIO1readStat16 SIO1_readStat16;
extern SIO1readStat32 SIO1_readStat32;
extern SIO1readMode16 SIO1_readMode16;
extern SIO1readMode32 SIO1_readMode32;
extern SIO1readCtrl16 SIO1_readCtrl16;
extern SIO1readCtrl32 SIO1_readCtrl32;
extern SIO1readBaud16 SIO1_readBaud16;
extern SIO1readBaud32 SIO1_readBaud32;
extern SIO1update SIO1_update;
extern SIO1registerCallback SIO1_registerCallback;

#endif

void clearDynarec(void);

void SetIsoFile(const char* filename);
void SetExeFile(const char* filename);
void SetAppPath(const char* filename);
void SetLdrFile(const char* ldrfile);
const char* GetIsoFile(void);
const char* GetExeFile(void);
const char* GetAppPath(void);
const char* GetLdrFile(void);
void SetCdOpenCaseTime(int64_t time);

#endif
