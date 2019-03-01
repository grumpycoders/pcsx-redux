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

namespace PCSX {

namespace SPU {

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
    bool iMute;        // mute mode
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

struct REVERBInfo {
    int StartAddr;  // reverb area start addr in samples
    int CurrAddr;   // reverb area curr addr in samples

    int VolLeft;
    int VolRight;
    int iLastRVBLeft;
    int iLastRVBRight;
    int iRVBLeft;
    int iRVBRight;

    int FB_SRC_A;     // (offset)
    int FB_SRC_B;     // (offset)
    int IIR_ALPHA;    // (coef.)
    int ACC_COEF_A;   // (coef.)
    int ACC_COEF_B;   // (coef.)
    int ACC_COEF_C;   // (coef.)
    int ACC_COEF_D;   // (coef.)
    int IIR_COEF;     // (coef.)
    int FB_ALPHA;     // (coef.)
    int FB_X;         // (coef.)
    int IIR_DEST_A0;  // (offset)
    int IIR_DEST_A1;  // (offset)
    int ACC_SRC_A0;   // (offset)
    int ACC_SRC_A1;   // (offset)
    int ACC_SRC_B0;   // (offset)
    int ACC_SRC_B1;   // (offset)
    int IIR_SRC_A0;   // (offset)
    int IIR_SRC_A1;   // (offset)
    int IIR_DEST_B0;  // (offset)
    int IIR_DEST_B1;  // (offset)
    int ACC_SRC_C0;   // (offset)
    int ACC_SRC_C1;   // (offset)
    int ACC_SRC_D0;   // (offset)
    int ACC_SRC_D1;   // (offset)
    int IIR_SRC_B1;   // (offset)
    int IIR_SRC_B0;   // (offset)
    int MIX_DEST_A0;  // (offset)
    int MIX_DEST_A1;  // (offset)
    int MIX_DEST_B0;  // (offset)
    int MIX_DEST_B1;  // (offset)
    int IN_COEF_L;    // (coef.)
    int IN_COEF_R;    // (coef.)
};

}  // namespace SPU

}  // namespace PCSX
