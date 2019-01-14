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

    // MAIN CHANNEL STRUCT

    // ADSR INFOS PER CHANNEL
    struct ADSRInfo {
        int AttackModeExp;
        long AttackTime;
        long DecayTime;
        long SustainLevel;
        int SustainModeExp;
        long SustainModeDec;
        long SustainTime;
        int ReleaseModeExp;
        unsigned long ReleaseVal;
        long ReleaseTime;
        long ReleaseStartTime;
        long ReleaseVol;
        long lTime;
        long lVolume;
    };

    struct ADSRInfoEx {
        int State;
        int AttackModeExp;
        int AttackRate;
        int DecayRate;
        int SustainLevel;
        int SustainModeExp;
        int SustainIncrease;
        int SustainRate;
        int ReleaseModeExp;
        int ReleaseRate;
        int EnvelopeVol;
        long lVolume;
        long lDummy1;
        long lDummy2;
    };

    struct SPUCHAN {
        int bNew;  // start flag

        int iSBPos;  // mixing stuff
        int spos;
        int sinc;
        int SB[32 + 32];  // Pete added another 32 dwords in 1.6 ... prevents overflow issues with gaussian/cubic
                          // interpolation (thanx xodnizel!), and can be used for even better interpolations, eh? :)
        int sval;

        unsigned char *pStart;  // start ptr into sound mem
        unsigned char *pCurr;   // current pos in sound mem
        unsigned char *pLoop;   // loop ptr in sound mem

        int bOn;           // is channel active (sample playing?)
        int bStop;         // is channel stopped (sample _can_ still be playing, ADSR Release phase)
        int bReverb;       // can we do reverb on this channel? must have ctrl register bit, to get active
        int iActFreq;      // current psx pitch
        int iUsedFreq;     // current pc pitch
        int iLeftVolume;   // left volume
        int iLeftVolRaw;   // left psx volume value
        int bIgnoreLoop;   // ignore loop bit, if an external loop address is used
        int iMute;         // mute mode
        int iRightVolume;  // right volume
        int iRightVolRaw;  // right psx volume value
        int iRawPitch;     // raw pitch (0...3fff)
        int iIrqDone;      // debug irq done flag
        int s_1;           // last decoding infos
        int s_2;
        int bRVBActive;    // reverb active flag
        int iRVBOffset;    // reverb offset
        int iRVBRepeat;    // reverb repeat
        int bNoise;        // noise active flag
        int bFMod;         // freq mod (0=off, 1=sound channel, 2=freq channel)
        int iRVBNum;       // another reverb helper
        int iOldNoise;     // old noise val for this channel
        ADSRInfo ADSR;     // active ADSR settings
        ADSRInfoEx ADSRX;  // next ADSR settings (will be moved to active on sample start)
    };
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
    void StartSound(SPUCHAN *pChannel);
    void VoiceChangeFrequency(SPUCHAN *pChannel);
    void FModChangeFrequency(SPUCHAN *pChannel, int ns);
    int iGetNoiseVal(SPUCHAN *pChannel);
    void StoreInterpolationVal(SPUCHAN *pChannel, int fa);
    int iGetInterpolationVal(SPUCHAN *pChannel);

    // reverb
    int g_buffer(int iOff); // get_buffer content helper: takes care about wraps
    void s_buffer(int iOff, int iVal);  // set_buffer content helper: takes care about wraps and clipping
    void s_buffer1(int iOff, int iVal);  // set_buffer (+1 sample) content helper: takes care about wraps and clipping
    void InitREVERB();
    void SetREVERB(unsigned short val);
    void StartREVERB(SPUCHAN *pChannel);
    void StoreREVERB(SPUCHAN *pChannel, int ns);
    int MixREVERBLeft(int ns);
    int MixREVERBRight();

    // xa
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

    int iUseXA = 1;
    int iVolume = 3;
    int iXAPitch = 1;
    int iSPUIRQWait = 1;
    int iSPUDebugMode = 0;
    int iRecordMode = 0;
    int iUseReverb = 2;
    int iUseInterpolation = 2;
    int iDisStereo = 0;
    int iUseDBufIrq = 0;
};

}  // namespace PCSX
