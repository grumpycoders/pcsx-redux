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

#include <SDL.h>
#include <stdint.h>

#include "json.hpp"

#include "core/decode_xa.h"
#include "main/settings.h"
#include "spu/adsr.h"
#include "spu/sdlsound.h"
#include "spu/types.h"

namespace PCSX {

namespace SPU {

class impl {
  public:
    using json = nlohmann::json;
    bool open();
    // SPU Functions
    long init(void);
    long shutdown(void);
    long close(void);
    // void playSample(unsigned char);
    void writeRegister(unsigned long, unsigned short);
    unsigned short readRegister(unsigned long);
    void writeDMA(unsigned short);
    unsigned short readDMA(void);
    void writeDMAMem(unsigned short *, int);
    void readDMAMem(unsigned short *, int);
    void playADPCMchannel(xa_decode_t *);
    void registerCallback(void (*callback)(void));
    long test(void);
    void about(void);

    struct SPUFreeze_t {
        char PluginName[8];
        uint32_t PluginVersion;
        uint32_t Size;
        unsigned char SPUPorts[0x200];
        unsigned char SPURam[0x80000];
        xa_decode_t xa;
        unsigned char *SPUInfo;
    };

    long freeze(uint32_t, SPUFreeze_t *);
    void async(uint32_t);
    void playCDDAchannel(short *, int);
    void registerCDDAVolume(void (*CDDAVcallback)(unsigned short, unsigned short));

    // num of channels
    static const size_t MAXCHAN = 24;

    void debug();
    bool configure();
    json getCfg() { return settings.serialize(); }
    void setCfg(const json &j) {
        if (j.count("SPU") && j["SPU"].is_object()) {
            settings.deserialize(j["SPU"]);
        } else {
            settings.reset();
        }
    }
    bool m_showDebug = false;
    bool m_showCfg = false;

  private:
    // sound buffer sizes
    // 400 ms complete sound buffer
    static const size_t SOUNDSIZE = 70560;
    // 137 ms test buffer... if less than that is buffered, a new upload will happen
    static const size_t TESTSIZE = 24192;

    // ~ 1 ms of data
    static const size_t NSSIZE = 45;

    // freeze
    void LoadStateV5(SPUFreeze_t *);
    void LoadStateUnknown(SPUFreeze_t *);

    // spu
    void MainThread();
    static int MainThreadTrampoline(void *arg) {
        impl *that = static_cast<impl *>(arg);
        that->MainThread();
        return 0;
    }
    void SetupStreams();
    void RemoveStreams();
    void SetupThread();
    void RemoveThread();
    void StartSound(SPUCHAN *pChannel);
    void VoiceChangeFrequency(SPUCHAN *pChannel);
    void FModChangeFrequency(SPUCHAN *pChannel, int ns);
    int iGetNoiseVal(SPUCHAN *pChannel);
    void StoreInterpolationVal(SPUCHAN *pChannel, int fa);
    int iGetInterpolationVal(SPUCHAN *pChannel);

    // registers
    void SoundOn(int start, int end, unsigned short val);
    void SoundOff(int start, int end, unsigned short val);
    void FModOn(int start, int end, unsigned short val);
    void NoiseOn(int start, int end, unsigned short val);
    void SetVolumeL(unsigned char ch, short vol);
    void SetVolumeR(unsigned char ch, short vol);
    void SetPitch(int ch, unsigned short val);
    void ReverbOn(int start, int end, unsigned short val);

    // reverb
    int g_buffer(int iOff);              // get_buffer content helper: takes care about wraps
    void s_buffer(int iOff, int iVal);   // set_buffer content helper: takes care about wraps and clipping
    void s_buffer1(int iOff, int iVal);  // set_buffer (+1 sample) content helper: takes care about wraps and clipping
    void InitREVERB();
    void SetREVERB(unsigned short val);
    void StartREVERB(SPUCHAN *pChannel);
    void StoreREVERB(SPUCHAN *pChannel, int ns);
    int MixREVERBLeft(int ns);
    int MixREVERBRight();

    // xa
    void MixXA();
    void FeedXA(xa_decode_t *xap);

    int bSPUIsOpen;

    // psx buffer / addresses

    unsigned short regArea[10000];
    unsigned short spuMem[256 * 1024];
    unsigned char *spuMemC;
    unsigned char *pSpuIrq = 0;
    unsigned char *pSpuBuffer;
    unsigned char *pMixIrq = 0;

    // user settings
#if 1
    typedef Setting<bool, true, typestring_is("Streaming")> Streaming;
    typedef Setting<int, 3, typestring_is("Volume")> Volume;
    typedef Setting<bool, true, typestring_is("Pitch")> StreamingPitch;
    typedef Setting<bool, true, typestring_is("IRQWait")> SPUIRQWait;
    typedef Setting<int, 2, typestring_is("Reverb")> Reverb;
    typedef Setting<int, 2, typestring_is("Interp")> Interpolation;
    typedef Setting<bool, false, typestring_is("Mono")> Mono;
    typedef Setting<bool, false, typestring_is("DBufIRQ")> DBufIRQ;
#else
    typedef Setting<bool, true, irqus::typestring<'S', 't', 'r', 'e', 'a', 'm', 'i', 'n', 'g'>> Streaming;
    typedef Setting<int, 3, irqus::typestring<'V', 'o', 'l', 'u', 'm', 'e'>> Volume;
    typedef Setting<bool, true, irqus::typestring<'P', 'i', 't', 'c', 'h'>> StreamingPitch;
    typedef Setting<bool, true, irqus::typestring<'I', 'R', 'Q', 'W', 'a', 'i', 't'>> SPUIRQWait;
    typedef Setting<int, 2, irqus::typestring<'R', 'e', 'v', 'e', 'r', 'b'>> Reverb;
    typedef Setting<int, 2, irqus::typestring<'I', 'n', 't', 'e', 'r', 'p'>> Interpolation;
    typedef Setting<bool, false, irqus::typestring<'M', 'o', 'n', 'o'>> Mono;
    typedef Setting<bool, false, irqus::typestring<'D', 'B', 'u', 'f', 'I', 'R', 'Q'>> DBufIRQ;
#endif
    Settings<Streaming, Volume, StreamingPitch, SPUIRQWait, Reverb, Interpolation, Mono, DBufIRQ> settings;

    // MAIN infos struct for each channel

    SPUCHAN s_chan[MAXCHAN + 1];  // channel + 1 infos (1 is security for fmod handling)
    REVERBInfo rvb;

    unsigned long dwNoiseVal = 1;  // global noise generator

    unsigned short spuCtrl = 0;  // some vars to store psx reg infos
    unsigned short spuStat = 0;
    unsigned short spuIrq = 0;
    unsigned long spuAddr = 0xffffffff;  // address into spu mem
    int bEndThread = 0;                  // thread handlers
    int bThreadEnded = 0;
    int bSpuInit = 0;

    SDL_Thread *hMainThread;
    unsigned long dwNewChannel = 0;  // flags for faster testing, if new channel starts

    void (*irqCallback)(void) = 0;  // func of main emu, called on spu irq
    void (*cddavCallback)(unsigned short, unsigned short) = 0;
    void (*irqQSound)(unsigned char *, long *, long) = 0;

    // certain globals (were local before, but with the new timeproc I need em global)

    const int f[5][2] = {{0, 0}, {60, 0}, {115, -52}, {98, -55}, {122, -60}};
    int SSumR[NSSIZE];
    int SSumL[NSSIZE];
    int iFMod[NSSIZE];
    int iCycle = 0;
    short *pS;

    int lastch = -1;       // last channel processed on spu irq in timer mode
    int lastns = 0;        // last ns pos
    int iSecureStart = 0;  // secure start counter
    int iSpuAsyncWait = 0;

    // REVERB info and timing vars...

    int *sRVBPlay = 0;
    int *sRVBEnd = 0;
    int *sRVBStart = 0;
    int iReverbOff = -1;  // some delay factor for reverb
    int iReverbRepeat = 0;
    int iReverbNum = 1;

    // XA
    xa_decode_t *xapGlobal = 0;

    unsigned long *XAFeed = NULL;
    unsigned long *XAPlay = NULL;
    unsigned long *XAStart = NULL;
    unsigned long *XAEnd = NULL;
    unsigned long XARepeat = 0;
    unsigned long XALastVal = 0;

    int iLeftXAVol = 32767;
    int iRightXAVol = 32767;

    int gauss_ptr = 0;
    int gauss_window[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    int &gvall0() { return gauss_window[gauss_ptr]; }
    int &gvall(int pos) { return gauss_window[(gauss_ptr + pos) & 3]; }
    int &gvalr0() { return gauss_window[4 + gauss_ptr]; }
    int &gvalr(int pos) { return gauss_window[4 + ((gauss_ptr + pos) & 3)]; }

    ADSR m_adsr;
    SDLsound m_sound;
    xa_decode_t m_cdda;

    // debug window
    unsigned m_selectedChannel = 0;
    uint32_t m_lastUpdated = 0;
    static const unsigned DEBUG_SAMPLES = 1024;
    enum { EMPTY = 0, DATA, NOISE, FMOD1, FMOD2, IRQ, MUTED } m_channelDebugTypes[MAXCHAN][DEBUG_SAMPLES];
    float m_channelDebugData[MAXCHAN][DEBUG_SAMPLES];
    unsigned m_currentDebugSample = 0;
};

}  // namespace SPU

}  // namespace PCSX
