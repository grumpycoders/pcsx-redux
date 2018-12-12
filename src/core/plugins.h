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

#include "psxcommon.h"

#ifndef _WIN32

typedef void* HWND;
#define CALLBACK

typedef long (*GPUopen)(unsigned long*, char*, char*);
typedef long (*SPUopen)(void);
typedef long (*PADopen)(unsigned long*);
typedef long (*NETopen)(unsigned long*);
typedef long (*SIO1open)(unsigned long*);

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef long(CALLBACK* GPUopen)(HWND);
typedef long(CALLBACK* SPUopen)(HWND);
typedef long(CALLBACK* PADopen)(HWND);
typedef long(CALLBACK* NETopen)(HWND);
typedef long(CALLBACK* SIO1open)(HWND);

#endif

#include "spu.h"

#include "decode_xa.h"
#include "psemu_plugin_defs.h"

int LoadPlugins();
void ReleasePlugins();
int OpenPlugins();
void ClosePlugins();

typedef unsigned long(CALLBACK* PSEgetLibType)(void);
typedef unsigned long(CALLBACK* PSEgetLibVersion)(void);
typedef char*(CALLBACK* PSEgetLibName)(void);

// GPU Functions
typedef long(CALLBACK* GPUinit)(void);
typedef long(CALLBACK* GPUshutdown)(void);
typedef long(CALLBACK* GPUclose)(void);
typedef void(CALLBACK* GPUwriteStatus)(uint32_t);
typedef void(CALLBACK* GPUwriteData)(uint32_t);
typedef void(CALLBACK* GPUwriteDataMem)(uint32_t*, int);
typedef uint32_t(CALLBACK* GPUreadStatus)(void);
typedef uint32_t(CALLBACK* GPUreadData)(void);
typedef void(CALLBACK* GPUreadDataMem)(uint32_t*, int);
typedef long(CALLBACK* GPUdmaChain)(uint32_t*, uint32_t);
typedef void(CALLBACK* GPUupdateLace)(void);
typedef long(CALLBACK* GPUconfigure)(void);
typedef long(CALLBACK* GPUtest)(void);
typedef void(CALLBACK* GPUabout)(void);
typedef void(CALLBACK* GPUmakeSnapshot)(void);
typedef void(CALLBACK* GPUtoggleDebug)(void);
typedef void(CALLBACK* GPUkeypressed)(int);
typedef void(CALLBACK* GPUdisplayText)(char*);
typedef struct {
    uint32_t ulFreezeVersion;
    uint32_t ulStatus;
    uint32_t ulControl[256];
    unsigned char psxVRam[1024 * 512 * 2];
} GPUFreeze_t;
typedef long(CALLBACK* GPUfreeze)(uint32_t, GPUFreeze_t*);
typedef long(CALLBACK* GPUgetScreenPic)(unsigned char*);
typedef long(CALLBACK* GPUshowScreenPic)(unsigned char*);
typedef void(CALLBACK* GPUclearDynarec)(void(CALLBACK* callback)(void));
typedef void(CALLBACK* GPUhSync)(int);
typedef void(CALLBACK* GPUvBlank)(int);
typedef void(CALLBACK* GPUvisualVibration)(uint32_t, uint32_t);
typedef void(CALLBACK* GPUcursor)(int, int, int);
typedef void(CALLBACK* GPUaddVertex)(short, short, s64, s64, s64);
typedef void(CALLBACK* GPUsetSpeed)(float);  // 1.0 = natural speed
typedef void(CALLBACK* GPUpgxpMemory)(unsigned int, unsigned char*);
typedef void(CALLBACK* GPUpgxpCacheVertex)(short sx, short sy, const unsigned char* _pVertex);

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

// CD-ROM Functions
typedef long(CALLBACK* CDRinit)(void);
typedef long(CALLBACK* CDRshutdown)(void);
typedef long(CALLBACK* CDRopen)(void);
typedef long(CALLBACK* CDRclose)(void);
typedef long(CALLBACK* CDRgetTN)(unsigned char*);
typedef long(CALLBACK* CDRgetTD)(unsigned char, unsigned char*);
typedef long(CALLBACK* CDRreadTrack)(unsigned char*);
typedef unsigned char*(CALLBACK* CDRgetBuffer)(void);
typedef unsigned char*(CALLBACK* CDRgetBufferSub)(void);
typedef long(CALLBACK* CDRconfigure)(void);
typedef long(CALLBACK* CDRtest)(void);
typedef void(CALLBACK* CDRabout)(void);
typedef long(CALLBACK* CDRplay)(unsigned char*);
typedef long(CALLBACK* CDRstop)(void);
typedef long(CALLBACK* CDRsetfilename)(char*);
struct CdrStat {
    uint32_t Type;
    uint32_t Status;
    unsigned char Time[3];
};
typedef long(CALLBACK* CDRgetStatus)(struct CdrStat*);
typedef char*(CALLBACK* CDRgetDriveLetter)(void);
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
typedef long(CALLBACK* CDRreadCDDA)(unsigned char, unsigned char, unsigned char, unsigned char*);
typedef long(CALLBACK* CDRgetTE)(unsigned char, unsigned char*, unsigned char*, unsigned char*);

// CD-ROM function pointers
extern CDRinit CDR_init;
extern CDRshutdown CDR_shutdown;
extern CDRopen CDR_open;
extern CDRclose CDR_close;
extern CDRtest CDR_test;
extern CDRgetTN CDR_getTN;
extern CDRgetTD CDR_getTD;
extern CDRreadTrack CDR_readTrack;
extern CDRgetBuffer CDR_getBuffer;
extern CDRgetBufferSub CDR_getBufferSub;
extern CDRplay CDR_play;
extern CDRstop CDR_stop;
extern CDRgetStatus CDR_getStatus;
extern CDRgetDriveLetter CDR_getDriveLetter;
extern CDRconfigure CDR_configure;
extern CDRabout CDR_about;
extern CDRsetfilename CDR_setfilename;
extern CDRreadCDDA CDR_readCDDA;
extern CDRgetTE CDR_getTE;

// SPU Functions
typedef long(CALLBACK* SPUinit)(void);
typedef long(CALLBACK* SPUshutdown)(void);
typedef long(CALLBACK* SPUclose)(void);
typedef void(CALLBACK* SPUplaySample)(unsigned char);
typedef void(CALLBACK* SPUwriteRegister)(unsigned long, unsigned short);
typedef unsigned short(CALLBACK* SPUreadRegister)(unsigned long);
typedef void(CALLBACK* SPUwriteDMA)(unsigned short);
typedef unsigned short(CALLBACK* SPUreadDMA)(void);
typedef void(CALLBACK* SPUwriteDMAMem)(unsigned short*, int);
typedef void(CALLBACK* SPUreadDMAMem)(unsigned short*, int);
typedef void(CALLBACK* SPUplayADPCMchannel)(xa_decode_t*);
typedef void(CALLBACK* SPUregisterCallback)(void(CALLBACK* callback)(void));
typedef long(CALLBACK* SPUconfigure)(void);
typedef long(CALLBACK* SPUtest)(void);
typedef void(CALLBACK* SPUabout)(void);
typedef struct {
    unsigned char PluginName[8];
    uint32_t PluginVersion;
    uint32_t Size;
    unsigned char SPUPorts[0x200];
    unsigned char SPURam[0x80000];
    xa_decode_t xa;
    unsigned char* SPUInfo;
} SPUFreeze_t;
typedef long(CALLBACK* SPUfreeze)(uint32_t, SPUFreeze_t*);
typedef void(CALLBACK* SPUasync)(uint32_t);
typedef void(CALLBACK* SPUplayCDDAchannel)(short*, int);

// SPU function pointers
extern SPUconfigure SPU_configure;
extern SPUabout SPU_about;
extern SPUinit SPU_init;
extern SPUshutdown SPU_shutdown;
extern SPUtest SPU_test;
extern SPUopen SPU_open;
extern SPUclose SPU_close;
extern SPUplaySample SPU_playSample;
extern SPUwriteRegister SPU_writeRegister;
extern SPUreadRegister SPU_readRegister;
extern SPUwriteDMA SPU_writeDMA;
extern SPUreadDMA SPU_readDMA;
extern SPUwriteDMAMem SPU_writeDMAMem;
extern SPUreadDMAMem SPU_readDMAMem;
extern SPUplayADPCMchannel SPU_playADPCMchannel;
extern SPUfreeze SPU_freeze;
extern SPUregisterCallback SPU_registerCallback;
extern SPUasync SPU_async;
extern SPUplayCDDAchannel SPU_playCDDAchannel;

// PAD Functions
typedef long(CALLBACK* PADconfigure)(void);
typedef void(CALLBACK* PADabout)(void);
typedef long(CALLBACK* PADinit)(long);
typedef long(CALLBACK* PADshutdown)(void);
typedef long(CALLBACK* PADtest)(void);
typedef long(CALLBACK* PADclose)(void);
typedef long(CALLBACK* PADquery)(void);
typedef long(CALLBACK* PADreadPort1)(PadDataS*);
typedef long(CALLBACK* PADreadPort2)(PadDataS*);
typedef long(CALLBACK* PADkeypressed)(void);
typedef unsigned char(CALLBACK* PADstartPoll)(int);
typedef unsigned char(CALLBACK* PADpoll)(unsigned char);
typedef void(CALLBACK* PADsetSensitive)(int);
typedef void(CALLBACK* PADregisterVibration)(void(CALLBACK* callback)(uint32_t, uint32_t));
typedef void(CALLBACK* PADregisterCursor)(void(CALLBACK* callback)(int, int, int));

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
extern PADpoll PAD1_poll;
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
extern PADpoll PAD2_poll;
extern PADsetSensitive PAD2_setSensitive;
extern PADregisterVibration PAD2_registerVibration;
extern PADregisterCursor PAD2_registerCursor;

// NET Functions
typedef long(CALLBACK* NETinit)(void);
typedef long(CALLBACK* NETshutdown)(void);
typedef long(CALLBACK* NETclose)(void);
typedef long(CALLBACK* NETconfigure)(void);
typedef long(CALLBACK* NETtest)(void);
typedef void(CALLBACK* NETabout)(void);
typedef void(CALLBACK* NETpause)(void);
typedef void(CALLBACK* NETresume)(void);
typedef long(CALLBACK* NETqueryPlayer)(void);
typedef long(CALLBACK* NETsendData)(void*, int, int);
typedef long(CALLBACK* NETrecvData)(void*, int, int);
typedef long(CALLBACK* NETsendPadData)(void*, int);
typedef long(CALLBACK* NETrecvPadData)(void*, int);

typedef struct {
    char EmuName[32];
    char CdromID[9];  // ie. 'SCPH12345', no \0 trailing character
    char CdromLabel[11];
    void* psxMem;
    GPUshowScreenPic GPU_showScreenPic;
    GPUdisplayText GPU_displayText;
    PADsetSensitive PAD_setSensitive;
    char GPUpath[256];  // paths must be absolute
    char SPUpath[256];
    char CDRpath[256];
    char MCD1path[256];
    char MCD2path[256];
    char BIOSpath[256];  // 'HLE' for internal bios
    char Unused[1024];
} netInfo;

typedef long(CALLBACK* NETsetInfo)(netInfo*);
typedef long(CALLBACK* NETkeypressed)(int);

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
typedef long(CALLBACK* SIO1init)(void);
typedef long(CALLBACK* SIO1shutdown)(void);
typedef long(CALLBACK* SIO1close)(void);
typedef long(CALLBACK* SIO1configure)(void);
typedef long(CALLBACK* SIO1test)(void);
typedef void(CALLBACK* SIO1about)(void);
typedef void(CALLBACK* SIO1pause)(void);
typedef void(CALLBACK* SIO1resume)(void);
typedef long(CALLBACK* SIO1keypressed)(int);
typedef void(CALLBACK* SIO1writeData8)(u8);
typedef void(CALLBACK* SIO1writeData16)(u16);
typedef void(CALLBACK* SIO1writeData32)(u32);
typedef void(CALLBACK* SIO1writeStat16)(u16);
typedef void(CALLBACK* SIO1writeStat32)(u32);
typedef void(CALLBACK* SIO1writeMode16)(u16);
typedef void(CALLBACK* SIO1writeMode32)(u32);
typedef void(CALLBACK* SIO1writeCtrl16)(u16);
typedef void(CALLBACK* SIO1writeCtrl32)(u32);
typedef void(CALLBACK* SIO1writeBaud16)(u16);
typedef void(CALLBACK* SIO1writeBaud32)(u32);
typedef u8(CALLBACK* SIO1readData8)(void);
typedef u16(CALLBACK* SIO1readData16)(void);
typedef u32(CALLBACK* SIO1readData32)(void);
typedef u16(CALLBACK* SIO1readStat16)(void);
typedef u32(CALLBACK* SIO1readStat32)(void);
typedef u16(CALLBACK* SIO1readMode16)(void);
typedef u32(CALLBACK* SIO1readMode32)(void);
typedef u16(CALLBACK* SIO1readCtrl16)(void);
typedef u32(CALLBACK* SIO1readCtrl32)(void);
typedef u16(CALLBACK* SIO1readBaud16)(void);
typedef u32(CALLBACK* SIO1readBaud32)(void);
typedef void(CALLBACK* SIO1update)(uint32_t);
typedef void(CALLBACK* SIO1registerCallback)(void(CALLBACK* callback)(void));

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

void CALLBACK clearDynarec(void);

void SetIsoFile(const char* filename);
void SetExeFile(const char* filename);
void SetAppPath(const char* filename);
void SetLdrFile(const char* ldrfile);
const char* GetIsoFile(void);
const char* GetExeFile(void);
const char* GetAppPath(void);
const char* GetLdrFile(void);
boolean UsingIso(void);
void SetCdOpenCaseTime(s64 time);

#ifdef __cplusplus
}
#endif
#endif
