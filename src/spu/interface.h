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

#include "core/decode_xa.h"
#include "core/spu.h"
#include "core/sstate.h"
#include "json.hpp"
#include "spu/adsr.h"
#include "spu/miniaudio.h"
#include "spu/types.h"
#include "support/settings.h"

namespace PCSX {

namespace SPU {

class impl : public SPUInterface {
  public:
    using json = nlohmann::json;
    bool open() final;
    // SPU Functions
    long init(void) final;
    long shutdown(void) final;
    long close(void) final;
    void wipeChannels();
    // void playSample(uint8_t);
    void writeRegister(uint32_t, uint16_t) final;
    uint16_t readRegister(uint32_t) final;
    void writeDMAMem(uint16_t *, int) final;
    void readDMAMem(uint16_t *, int) final;
    virtual void playADPCMchannel(xa_decode_t *) final;

    void save(SaveStates::SPU &) final;
    void load(const SaveStates::SPU &) final;

    void async(uint32_t) final;
    void playCDDAchannel(int16_t *, int) final;
    void registerCDDAVolume(void (*CDDAVcallback)(uint16_t, uint16_t));

    // num of channels
    static const size_t MAXCHAN = 24;

    void debug() final;
    bool configure() final;
    json getCfg() final { return settings.serialize(); }
    void setCfg(const json &j) final {
        if (j.count("SPU") && j["SPU"].is_object()) {
            settings.deserialize(j["SPU"]);
        } else {
            settings.reset();
        }
    }

  private:
    // sound buffer sizes
    // 400 ms complete sound buffer
    static const size_t SOUNDSIZE = 70560;
    // 137 ms test buffer... if less than that is buffered, a new upload will happen
    static const size_t TESTSIZE = 24192;

    // ~ 1 ms of data
    static const size_t NSSIZE = 45;

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
    void SoundOn(int start, int end, uint16_t val);
    void SoundOff(int start, int end, uint16_t val);
    void FModOn(int start, int end, uint16_t val);
    void NoiseOn(int start, int end, uint16_t val);
    void SetVolumeL(uint8_t ch, int16_t vol);
    void SetVolumeR(uint8_t ch, int16_t vol);
    void SetPitch(int ch, uint16_t val);
    void ReverbOn(int start, int end, uint16_t val);

    // reverb
    int g_buffer(int iOff);              // get_buffer content helper: takes care about wraps
    void s_buffer(int iOff, int iVal);   // set_buffer content helper: takes care about wraps and clipping
    void s_buffer1(int iOff, int iVal);  // set_buffer (+1 sample) content helper: takes care about wraps and clipping
    void InitREVERB();
    void SetREVERB(uint16_t val);
    void StartREVERB(SPUCHAN *pChannel);
    void StoreREVERB(SPUCHAN *pChannel, int ns);
    int MixREVERBLeft(int ns);
    int MixREVERBRight();

    // xa
    void FeedXA(xa_decode_t *xap);

    int bSPUIsOpen;

    // psx buffer / addresses
    uint16_t regArea[10000];
    uint16_t spuMem[256 * 1024];
    uint8_t *spuMemC;
    uint8_t *pSpuIrq = 0;
    uint8_t *pSpuBuffer;
    uint8_t *pMixIrq = 0;

    // user settings
    typedef Setting<bool, TYPESTRING("Streaming"), true> Streaming;
    typedef Setting<int, TYPESTRING("Volume"), 3> Volume;
    typedef Setting<bool, TYPESTRING("Pitch"), false> StreamingPitch;
    typedef Setting<bool, TYPESTRING("IRQWait"), true> SPUIRQWait;
    typedef Setting<int, TYPESTRING("Reverb"), 2> Reverb;
    typedef Setting<int, TYPESTRING("Interp"), 2> Interpolation;
    typedef Setting<bool, TYPESTRING("Mono")> Mono;
    typedef Setting<bool, TYPESTRING("DBufIRQ")> DBufIRQ;
    typedef Setting<bool, TYPESTRING("Mute")> Mute;
    Settings<Streaming, Volume, StreamingPitch, SPUIRQWait, Reverb, Interpolation, Mono, DBufIRQ, Mute> settings;

    // MAIN infos struct for each channel

    SPUCHAN s_chan[MAXCHAN + 1];  // channel + 1 infos (1 is security for fmod handling)
    REVERBInfo rvb;

    uint32_t dwNoiseVal = 1;  // global noise generator

    uint16_t spuCtrl = 0;  // some vars to store psx reg infos
    uint16_t spuStat = 0;
    uint16_t spuIrq = 0;
    uint32_t spuAddr = 0xffffffff;  // address into spu mem
    int bEndThread = 0;             // thread handlers
    int bThreadEnded = 0;
    int bSpuInit = 0;

    SDL_Thread *hMainThread;
    uint32_t dwNewChannel = 0;  // flags for faster testing, if new channel starts

    void (*cddavCallback)(uint16_t, uint16_t) = 0;

    // certain globals (were local before, but with the new timeproc I need em global)

    const int f[5][2] = {{0, 0}, {60, 0}, {115, -52}, {98, -55}, {122, -60}};
    int SSumR[NSSIZE];
    int SSumL[NSSIZE];
    int iFMod[NSSIZE];
    int iCycle = 0;
    int16_t *pS;

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

    int iLeftXAVol = 32767;
    int iRightXAVol = 32767;

    int gauss_ptr = 0;
    int gauss_window[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    int &gvall0() { return gauss_window[gauss_ptr]; }
    int &gvall(int pos) { return gauss_window[(gauss_ptr + pos) & 3]; }
    int &gvalr0() { return gauss_window[4 + gauss_ptr]; }
    int &gvalr(int pos) { return gauss_window[4 + ((gauss_ptr + pos) & 3)]; }

    ADSR m_adsr;
    MiniAudio m_sound = {settings.get<Mute>().value};
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
