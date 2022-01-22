/***************************************************************************
                            spu.c  -  description
                             -------------------
    begin                : Wed May 15 2002
    copyright            : (C) 2002 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2022/01/11 - Pcsx-Redux
// - Breaking up the monolithic MainThread method into the manageable methods (more scalable)
// - Code Refactoring
// - Decreasing the probability of losing voice data by removing waiting cycles (while loop at feedStreamData)
// - Adding a temporary queue in the circular.h to decrease voice data loss and remove exception throwing
//
// 2004/09/19 - Pete
// - added option: IRQ handling in the decoded sound buffer areas (Crash Team Racing)
//
// 2004/09/18 - Pete
// - changed global channel var handling to local pointers (hopefully it will help LDChen's port)
//
// 2004/04/22 - Pete
// - finally fixed frequency modulation and made some cleanups
//
// 2003/04/07 - Eric
// - adjusted cubic interpolation algorithm
//
// 2003/03/16 - Eric
// - added cubic interpolation
//
// 2003/03/01 - linuzappz
// - libraryName changes using ALSA
//
// 2003/02/28 - Pete
// - added option for type of interpolation
// - adjusted spu irqs again (Thousant Arms, Valkyrie Profile)
// - added MONO support for MSWindows DirectSound
//
// 2003/02/20 - kode54
// - amended interpolation code, goto GOON could skip initialization of gpos and cause segfault
//
// 2003/02/19 - kode54
// - moved SPU IRQ handler and changed sample flag processing
//
// 2003/02/18 - kode54
// - moved ADSR calculation outside of the sample decode loop, somehow I doubt that
//   ADSR timing is relative to the frequency at which a sample is played... I guess
//   this remains to be seen, and I don't know whether ADSR is applied to noise channels...
//
// 2003/02/09 - kode54
// - one-shot samples now process the end block before stopping
// - in light of removing fmod hack, now processing ADSR on frequency channel as well
//
// 2003/02/08 - kode54
// - replaced easy interpolation with gaussian
// - removed fmod averaging hack
// - changed .sinc to be updated from .iRawPitch, no idea why it wasn't done this way already (<- Pete: because I
// sometimes fail to see the obvious, haharhar :)
//
// 2003/02/08 - linuzappz
// - small bugfix for one usleep that was 1 instead of 1000
// - added settings.get<Mono>() for no stereo (Linux)
//
// 2003/01/22 - Pete
// - added easy interpolation & small noise adjustments
//
// 2003/01/19 - Pete
// - added Neill's reverb
//
// 2003/01/12 - Pete
// - added recording window handlers
//
// 2003/01/06 - Pete
// - added Neill's ADSR timings
//
// 2002/12/28 - Pete
// - adjusted spu irq handling, fmod handling and loop handling
//
// 2002/08/14 - Pete
// - added extra reverb
//
// 2002/06/08 - linuzappz
// - SPUupdate changed for SPUasync
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include <chrono>
#include <future>
#include <thread>

#include "spu/adsr.h"
#include "spu/externals.h"
#include "spu/gauss.h"
#include "spu/interface.h"
////////////////////////////////////////////////////////////////////////
// globals
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// CODE AREA
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// helpers for simple interpolation

//
// easy interpolation on upsampling, no special filter, just "Pete's common sense" tm
//
// instead of having n equal sample values in a row like:
//       ____
//           |____
//
// we compare the current delta change with the next delta change.
//
// if curr_delta is positive,
//
//  - and next delta is smaller (or changing direction):
//         \.
//          -__
//
//  - and next delta significant (at least twice) bigger:
//         --_
//            \.
//
//  - and next delta is nearly same:
//          \.
//           \.
//
//
// if curr_delta is negative,
//
//  - and next delta is smaller (or changing direction):
//          _--
//         /
//
//  - and next delta significant (at least twice) bigger:
//            /
//         __-
//
//  - and next delta is nearly same:
//           /
//          /
//

static inline void InterpolateUp(PCSX::SPU::SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    if (SB[32].value == 1)  // flag == 1? calc step and set flag... and don't change the value in this pass
    {
        const int id1 = SB[30].value - SB[29].value;  // curr delta to next val
        const int id2 = SB[31].value - SB[30].value;  // and next delta to next-next val :)

        SB[32].value = 0;

        if (id1 > 0)  // curr delta positive
        {
            if (id2 < id1) {
                SB[28].value = id1;
                SB[32].value = 2;
            } else if (id2 < (id1 << 1))
                SB[28].value = (id1 * pChannel->data.get<PCSX::SPU::Chan::sinc>().value) / 0x10000L;
            else
                SB[28].value = (id1 * pChannel->data.get<PCSX::SPU::Chan::sinc>().value) / 0x20000L;
        } else  // curr delta negative
        {
            if (id2 > id1) {
                SB[28].value = id1;
                SB[32].value = 2;
            } else if (id2 > (id1 << 1))
                SB[28].value = (id1 * pChannel->data.get<PCSX::SPU::Chan::sinc>().value) / 0x10000L;
            else
                SB[28].value = (id1 * pChannel->data.get<PCSX::SPU::Chan::sinc>().value) / 0x20000L;
        }
    } else if (SB[32].value == 2)  // flag 1: calc step and set flag... and don't change the value in this pass
    {
        SB[32].value = 0;

        SB[28].value = (SB[28].value * pChannel->data.get<PCSX::SPU::Chan::sinc>().value) / 0x20000L;
        if (pChannel->data.get<PCSX::SPU::Chan::sinc>().value <= 0x8000)
            SB[29].value =
                SB[30].value - (SB[28].value * ((0x10000 / pChannel->data.get<PCSX::SPU::Chan::sinc>().value) - 1));
        else
            SB[29].value += SB[28].value;
    } else  // no flags? add bigger val (if possible), calc smaller step, set flag1
        SB[29].value += SB[28].value;
}

//
// even easier interpolation on downsampling, also no special filter, again just "Pete's common sense" tm
//

static inline void InterpolateDown(PCSX::SPU::SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    if (pChannel->data.get<PCSX::SPU::Chan::sinc>().value >= 0x20000L)  // we would skip at least one val?
    {
        SB[29].value += (SB[30].value - SB[29].value) / 2;                  // add easy weight
        if (pChannel->data.get<PCSX::SPU::Chan::sinc>().value >= 0x30000L)  // we would skip even more vals?
            SB[29].value += (SB[31].value - SB[30].value) / 2;              // add additional next weight
    }
}

////////////////////////////////////////////////////////////////////////
// helpers for gauss interpolation

#define gval0 (((int16_t *)(&SB[29].value))[gpos])
#define gval(x) (((int16_t *)(&SB[29].value))[(gpos + x) & 3])

////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// START SOUND... called by main thread to setup a new sound on a channel
////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::StartSound(SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    m_adsr.start(pChannel);
    StartREVERB(pChannel);

    pChannel->pCurr = pChannel->pStart;  // set sample start

    pChannel->data.get<PCSX::SPU::Chan::s_1>().value = 0;  // init mixing vars
    pChannel->data.get<PCSX::SPU::Chan::s_2>().value = 0;
    pChannel->data.get<PCSX::SPU::Chan::SBPos>().value = 28;

    pChannel->data.get<PCSX::SPU::Chan::New>().value = false;  // init channel flags
    pChannel->data.get<PCSX::SPU::Chan::Stop>().value = false;
    pChannel->data.get<PCSX::SPU::Chan::On>().value = true;

    SB[29].value = 0;  // init our interpolation helpers
    SB[30].value = 0;

    if (settings.get<Interpolation>() >= 2)  // gauss interpolation?
    {
        pChannel->data.get<PCSX::SPU::Chan::spos>().value = 0x30000L;
        SB[28].value = 0;
    }  // -> start with more decoding
    else {
        pChannel->data.get<PCSX::SPU::Chan::spos>().value = 0x10000L;
        SB[31].value = 0;
    }  // -> no/simple interpolation starts with one 44100 decoding
}

////////////////////////////////////////////////////////////////////////
// ALL KIND OF HELPERS
////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::VoiceChangeFrequency(SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    pChannel->data.get<PCSX::SPU::Chan::UsedFreq>().value =
        pChannel->data.get<PCSX::SPU::Chan::ActFreq>().value;  // -> take it and calc steps
    pChannel->data.get<PCSX::SPU::Chan::sinc>().value = pChannel->data.get<PCSX::SPU::Chan::RawPitch>().value << 4;
    if (!pChannel->data.get<PCSX::SPU::Chan::sinc>().value) pChannel->data.get<PCSX::SPU::Chan::sinc>().value = 1;
    if (settings.get<Interpolation>() == 1) SB[32].value = 1;  // -> freq change in simle imterpolation mode: set flag
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::FModChangeFrequency(SPUCHAN *pChannel, int ns) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    int NP = pChannel->data.get<PCSX::SPU::Chan::RawPitch>().value;

    NP = ((32768L + iFMod[ns]) * NP) / 32768L;

    if (NP > 0x3fff) NP = 0x3fff;
    if (NP < 0x1) NP = 0x1;

    NP = (44100L * NP) / (4096L);  // calc frequency

    pChannel->data.get<PCSX::SPU::Chan::ActFreq>().value = NP;
    pChannel->data.get<PCSX::SPU::Chan::UsedFreq>().value = NP;
    pChannel->data.get<PCSX::SPU::Chan::sinc>().value = (((NP / 10) << 16) / 4410);
    if (!pChannel->data.get<PCSX::SPU::Chan::sinc>().value) pChannel->data.get<PCSX::SPU::Chan::sinc>().value = 1;
    if (settings.get<Interpolation>() == 1) SB[32].value = 1;  // freq change in simple interpolation mode

    iFMod[ns] = 0;
}

////////////////////////////////////////////////////////////////////////

// noise handler... just produces some noise data
// surely wrong... and no noise frequency (spuCtrl&0x3f00) will be used...
// and sometimes the noise will be used as fmod modulation... pfff

inline int PCSX::SPU::impl::iGetNoiseVal(SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    int fa;

    if ((dwNoiseVal <<= 1) & 0x80000000L) {
        dwNoiseVal ^= 0x0040001L;
        fa = ((dwNoiseVal >> 2) & 0x7fff);
        fa = -fa;
    } else
        fa = (dwNoiseVal >> 2) & 0x7fff;

    // mmm... depending on the noise freq we allow bigger/smaller changes to the previous val
    fa = pChannel->data.get<PCSX::SPU::Chan::OldNoise>().value +
         ((fa - pChannel->data.get<PCSX::SPU::Chan::OldNoise>().value) / ((0x001f - ((spuCtrl & 0x3f00) >> 9)) + 1));
    if (fa > 32767L) fa = 32767L;
    if (fa < -32767L) fa = -32767L;
    pChannel->data.get<PCSX::SPU::Chan::OldNoise>().value = fa;

    if (settings.get<Interpolation>() < 2)  // no gauss/cubic interpolation?
        SB[29].value = fa;                  // -> store noise val in "current sample" slot
    return fa;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::StoreInterpolationVal(SPUCHAN *pChannel, int fa) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    if (pChannel->data.get<PCSX::SPU::Chan::FMod>().value == 2)  // fmod freq channel
        SB[29].value = fa;
    else {
        if ((spuCtrl & 0x4000) == 0)
            fa = 0;  // muted?
        else         // else adjust
        {
            if (fa > 32767L) fa = 32767L;
            if (fa < -32767L) fa = -32767L;
        }

        if (settings.get<Interpolation>() >= 2)  // gauss/cubic interpolation
        {
            int gpos = SB[28].value;
            gval0 = fa;
            gpos = (gpos + 1) & 3;
            SB[28].value = gpos;
        } else if (settings.get<Interpolation>() == 1)  // simple interpolation
        {
            SB[28].value = 0;
            SB[29].value = SB[30].value;  // -> helpers for simple linear interpolation: delay real val for two slots,
                                          // and calc the two deltas, for a 'look at the future behaviour'
            SB[30].value = SB[31].value;
            SB[31].value = fa;
            SB[32].value = 1;  // -> flag: calc new interolation
        } else
            SB[29].value = fa;  // no interpolation
    }
}

////////////////////////////////////////////////////////////////////////

inline int PCSX::SPU::impl::iGetInterpolationVal(SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    int fa;

    if (pChannel->data.get<PCSX::SPU::Chan::FMod>().value == 2) return SB[29].value;

    switch (settings.get<Interpolation>()) {
        //--------------------------------------------------//
        case 3:  // cubic interpolation
        {
            long xd;
            int gpos;
            xd = ((pChannel->data.get<PCSX::SPU::Chan::spos>().value) >> 1) + 1;
            gpos = SB[28].value;

            fa = gval(3) - 3 * gval(2) + 3 * gval(1) - gval0;
            fa *= (xd - (2 << 15)) / 6;
            fa >>= 15;
            fa += gval(2) - gval(1) - gval(1) + gval0;
            fa *= (xd - (1 << 15)) >> 1;
            fa >>= 15;
            fa += gval(1) - gval0;
            fa *= xd;
            fa >>= 15;
            fa = fa + gval0;

        } break;
        //--------------------------------------------------//
        case 2:  // gauss interpolation
        {
            int vl, vr;
            int gpos;
            vl = (pChannel->data.get<PCSX::SPU::Chan::spos>().value >> 6) & ~3;
            gpos = SB[28].value;
            vr = (Gauss::gauss[vl] * gval0) & ~2047;
            vr += (Gauss::gauss[vl + 1] * gval(1)) & ~2047;
            vr += (Gauss::gauss[vl + 2] * gval(2)) & ~2047;
            vr += (Gauss::gauss[vl + 3] * gval(3)) & ~2047;
            fa = vr >> 11;
        } break;
        //--------------------------------------------------//
        case 1:  // simple interpolation
        {
            if (pChannel->data.get<PCSX::SPU::Chan::sinc>().value < 0x10000L)  // -> upsampling?
                InterpolateUp(pChannel);                                       // --> interpolate up
            else
                InterpolateDown(pChannel);  // --> else down
            fa = SB[29].value;
        } break;
        //--------------------------------------------------//
        default:  // no interpolation
        {
            fa = SB[29].value;
        } break;
            //--------------------------------------------------//
    }

    return fa;
}

////////////////////////////////////////////////////////////////////////
// MAIN SPU FUNCTION
// here is the main job handler... thread, timer or direct func call
// basically the whole sound processing is done in this fat func!
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::MainThread() {
    MainThreadVariables mVars;
    while (!bEndThread)  // until we are shutting down
    {
        mVars.voldiv = 4 - settings.get<Volume>();
        ///////////////////////////////////////////////////////////////////
        // ok, at the beginning we are looking if there is
        // enuff free place in the dsound/oss buffer to
        // fill in new data, or if there is a new channel to start.
        // if not, we wait (thread) or return (timer/spuasync)
        // until enuff free place is available/a new channel gets started
        ///////////////////////////////////////////////////////////////////
        // new channel should start immedately? (at least one bit 0 ... MAXCHANNEL is set?)
        // set iSecure
        // 0: no new channel should start
        iSecureStart = dwNewChannel ? iSecureStart + 1 : 0;
        // (if it is set 5 times - that means on 5 tries a new samples has been started -
        // in a row, we will reset it, to give the sound update a chance)
        if (iSecureStart > 5) iSecureStart = 0;
        while (!iSecureStart && !bEndThread &&              // no new start? no thread end?
               (m_audioOut.getBytesBuffered() > TESTSIZE))  // and still enuff data in sound buffer?
        {
            iSecureStart = 0;  // reset secure
            using namespace std::chrono_literals;
            std::this_thread::sleep_for(5ms);
            // if a new channel kicks in (or, of course, sound buffer runs low), we will leave the loop
            if (dwNewChannel) iSecureStart = 1;
        }
        // continue from irq handling in timer mode?
        if (lastch >= 0)  // will be -1 if no continue is pending
        {
            mVars.ch = lastch;
            mVars.ns = lastns;
            lastch = -1;  // -> setup all kind of vars to continue
            mVars.pChannel = &s_chan[mVars.ch];
            goto GOON;  // -> directly jump to the continue point
        }
        mVars.tmpCapVoice1Index = capBufVoiceIndex;
        mVars.tmpCapVoice3Index = capBufVoiceIndex;
        //--------------------------------------------------//
        //- main channel loop                              -//
        //--------------------------------------------------//
        {
            mVars.pChannel = s_chan;
            for (mVars.ch = 0; mVars.ch < MAXCHAN; mVars.ch++,
                mVars.pChannel++)  // loop em all... we will collect 1 ms of sound of each playing channel
            {
                if (mVars.pChannel->data.get<PCSX::SPU::Chan::New>().value) {
                    StartSound(mVars.pChannel);        // start new sound
                    dwNewChannel &= ~(1 << mVars.ch);  // clear new channel bit
                }
                if (!mVars.pChannel->data.get<PCSX::SPU::Chan::On>().value) {
                    // Although the voices may stop outputting audio, the capture buffer is still filling up.
                    if (pMixIrq && mVars.ch == 1) {
                        std::unique_lock<std::mutex> lock(cbMtx);
                        for (int c = 0; c < NSSIZE; c++) spuMem[mVars.tmpCapVoice1Index + c + 0x400] = 0;
                        mVars.tmpCapVoice1Index = (mVars.tmpCapVoice1Index + NSSIZE) % 0x200;
                    } else if (pMixIrq && mVars.ch == 3) {
                        std::unique_lock<std::mutex> lock(cbMtx);
                        for (int c = 0; c < NSSIZE; c++) spuMem[mVars.tmpCapVoice3Index + c + 0x600] = 0;
                        mVars.tmpCapVoice3Index = (mVars.tmpCapVoice3Index + NSSIZE) % 0x200;
                    }
                    continue;  // channel not playing? next
                }
                if (mVars.pChannel->data.get<PCSX::SPU::Chan::ActFreq>().value !=
                    mVars.pChannel->data.get<PCSX::SPU::Chan::UsedFreq>().value)  // new psx frequency?
                    VoiceChangeFrequency(mVars.pChannel);
                mVars.ns = 0;
                while (mVars.ns < NSSIZE)  // loop until 1 ms of data is reached
                {
                    if (mVars.pChannel->data.get<PCSX::SPU::Chan::FMod>().value == 1 &&
                        iFMod[mVars.ns])  // fmod freq channel
                        FModChangeFrequency(mVars.pChannel, mVars.ns);
                    while (mVars.pChannel->data.get<PCSX::SPU::Chan::spos>().value >= 0x10000L) {
                        if (mVars.pChannel->data.get<PCSX::SPU::Chan::SBPos>().value == 28)  // 28 reached?
                        {
                            mVars.start = mVars.pChannel->pCurr;  // set up the current pos
                            if (mVars.start == (uint8_t *)-1)     // special "stop" sign
                            {
                                StopSign(mVars);
                                goto ENDX;  // and done for this channel
                            }
                            // spu irq handler here? mmm... do it later
                            SBPos_28(mVars);
                        GOON:;
                        }
                        mVars.fa = mVars.pChannel->data.get<PCSX::SPU::Chan::SB>()
                                       .value[mVars.pChannel->data.get<PCSX::SPU::Chan::SBPos>().value++]
                                       .value;  // get sample data

                        StoreInterpolationVal(mVars.pChannel, mVars.fa);  // store val for later interpolation
                        mVars.pChannel->data.get<PCSX::SPU::Chan::spos>().value -= 0x10000L;
                    }
                    ////////////////////////////////////////////////
                    GetNoiseOrSampleMixedSample(mVars);
                    FModFreqChannel(mVars);
                    ////////////////////////////////////////////////
                    // ok, go on until 1 ms data of this channel is collected
                    mVars.ns++;
                    mVars.pChannel->data.get<PCSX::SPU::Chan::spos>().value +=
                        mVars.pChannel->data.get<PCSX::SPU::Chan::sinc>().value;
                }
            ENDX:;
            }
        }
        // Write from our temporary capture buffer to the actual SPU RAM.
        writeCaptureBufferCD(NSSIZE);
        //---------------------------------------------------//
        //- here we have another 1 ms of sound data
        //---------------------------------------------------//
        MixAllChannels(mVars);
        if (pMixIrq) PMixIrq(mVars);
        InitREVERB();
        FeedStreamData(mVars);
    }
    // end of big main loop...
    bThreadEnded = 1;
}
void PCSX::SPU::impl::FModFreqChannel(MainThreadVariables &mVars) {
    if (mVars.pChannel->data.get<PCSX::SPU::Chan::FMod>().value == 2)  // fmod freq channel
        iFMod[mVars.ns] = mVars.pChannel->data.get<PCSX::SPU::Chan::sval>()
                              .value;  // -> store 1T sample data, use that to do fmod on next channel
    else                               // no fmod freq channel
    {
        //////////////////////////////////////////////
        // ok, left/right sound volume (psx volume goes from 0 ... 0x3fff)

        if (mVars.pChannel->data.get<PCSX::SPU::Chan::Mute>().value)
            mVars.pChannel->data.get<PCSX::SPU::Chan::sval>().value = 0;  // debug mute
        else {
            SSumL[mVars.ns] += (mVars.pChannel->data.get<PCSX::SPU::Chan::sval>().value *
                                mVars.pChannel->data.get<PCSX::SPU::Chan::LeftVolume>().value) /
                               0x4000L;
            SSumR[mVars.ns] += (mVars.pChannel->data.get<PCSX::SPU::Chan::sval>().value *
                                mVars.pChannel->data.get<PCSX::SPU::Chan::RightVolume>().value) /
                               0x4000L;
        }

        //////////////////////////////////////////////
        // now let us store sound data for reverb

        if (mVars.pChannel->data.get<PCSX::SPU::Chan::RVBActive>().value) StoreREVERB(mVars.pChannel, mVars.ns);
    }
}

void PCSX::SPU::impl::GetNoiseOrSampleMixedSample(MainThreadVariables &mVars) {
    if (mVars.pChannel->data.get<PCSX::SPU::Chan::Noise>().value)
        mVars.fa = iGetNoiseVal(mVars.pChannel);  // get noise val
    else
        mVars.fa = iGetInterpolationVal(mVars.pChannel);  // get sample val

    int32_t mixedSample = (m_adsr.mix(mVars.pChannel) * mVars.fa) / 1023;  // mix adsr
    mVars.pChannel->data.get<PCSX::SPU::Chan::sval>().value = mixedSample;

    // Capture buffer should contain voice1/3 sample after any adsr processing but before volume
    // processing?
    mixedSample = std::min(0xFFFF, std::max(-0xFFFF, mixedSample));
    if (pMixIrq && mVars.ch == 1) {
        std::unique_lock<std::mutex> lock(cbMtx);
        spuMem[mVars.tmpCapVoice1Index + 0x400] = mixedSample;
        mVars.tmpCapVoice1Index = (mVars.tmpCapVoice1Index + 1) % 0x200;
    } else if (pMixIrq && mVars.ch == 3) {
        std::unique_lock<std::mutex> lock(cbMtx);
        spuMem[mVars.tmpCapVoice3Index + 0x600] = mixedSample;
        mVars.tmpCapVoice3Index = (mVars.tmpCapVoice3Index + 1) % 0x200;
    }
}
void PCSX::SPU::impl::SBPos_28(MainThreadVariables &mVars) {
    mVars.pChannel->data.get<PCSX::SPU::Chan::SBPos>().value = 0;

    mVars.s_1 = mVars.pChannel->data.get<PCSX::SPU::Chan::s_1>().value;
    mVars.s_2 = mVars.pChannel->data.get<PCSX::SPU::Chan::s_2>().value;

    mVars.predict_nr = (int)*mVars.start;
    mVars.start++;
    mVars.shift_factor = mVars.predict_nr & 0xf;
    mVars.predict_nr >>= 4;
    mVars.flags = (int)*mVars.start;
    mVars.start++;

    // -------------------------------------- //
    for (mVars.nSample = 0; mVars.nSample < 28; mVars.start++) {
        mVars.d = (int)*mVars.start;
        mVars.s = ((mVars.d & 0xf) << 12);
        if (mVars.s & 0x8000) mVars.s |= 0xffff0000;

        mVars.fa = (mVars.s >> mVars.shift_factor);
        mVars.fa = mVars.fa + ((mVars.s_1 * f[mVars.predict_nr][0]) >> 6) + ((mVars.s_2 * f[mVars.predict_nr][1]) >> 6);
        mVars.s_2 = mVars.s_1;
        mVars.s_1 = mVars.fa;
        mVars.s = ((mVars.d & 0xf0) << 8);

        mVars.pChannel->data.get<PCSX::SPU::Chan::SB>().value[mVars.nSample++].value = mVars.fa;

        if (mVars.s & 0x8000) mVars.s |= 0xffff0000;
        mVars.fa = (mVars.s >> mVars.shift_factor);
        mVars.fa = mVars.fa + ((mVars.s_1 * f[mVars.predict_nr][0]) >> 6) + ((mVars.s_2 * f[mVars.predict_nr][1]) >> 6);
        mVars.s_2 = mVars.s_1;
        mVars.s_1 = mVars.fa;

        mVars.pChannel->data.get<PCSX::SPU::Chan::SB>().value[mVars.nSample++].value = mVars.fa;
    }

    //////////////////////////////////////////// irq check
    IrqCheck(mVars);
    //////////////////////////////////////////// flag handler
    FlagHandler(mVars);

    mVars.pChannel->pCurr = mVars.start;  // store values for next cycle
    mVars.pChannel->data.get<PCSX::SPU::Chan::s_1>().value = mVars.s_1;
    mVars.pChannel->data.get<PCSX::SPU::Chan::s_2>().value = mVars.s_2;

    ////////////////////////////////////////////

    if (mVars.bIRQReturn)  // special return for "spu irq - wait for cpu action"
    {
        using namespace std::chrono_literals;
        mVars.bIRQReturn = 0;
        auto dwWatchTime = std::chrono::steady_clock::now() + 2500ms;

        while (iSpuAsyncWait && !bEndThread && std::chrono::steady_clock::now() < dwWatchTime) {
            std::this_thread::sleep_for(1ms);
        }
    }
}
void PCSX::SPU::impl::StopSign(MainThreadVariables &mVars) {
    mVars.pChannel->data.get<PCSX::SPU::Chan::On>().value = false;  // -> turn everything off
    mVars.pChannel->ADSRX.get<exVolume>().value = 0;
    mVars.pChannel->ADSRX.get<exEnvelopeVol>().value = 0;
    // Although the voices may stop outputting audio, the capture buffer is still filling
    // up. At this point, ns samples are already filled, we need (NSSIZE-ns) more samples.
    if (pMixIrq && mVars.ch == 1) {
        std::unique_lock<std::mutex> lock(cbMtx);
        for (int c = mVars.ns; c < NSSIZE; c++) spuMem[mVars.tmpCapVoice1Index + c + 0x400] = 0;
        mVars.tmpCapVoice1Index = (mVars.tmpCapVoice1Index + (NSSIZE - mVars.ns)) % 0x200;
    } else if (pMixIrq && mVars.ch == 3) {
        std::unique_lock<std::mutex> lock(cbMtx);
        for (int c = mVars.ns; c < NSSIZE; c++) spuMem[mVars.tmpCapVoice3Index + c + 0x600] = 0;
        mVars.tmpCapVoice3Index = (mVars.tmpCapVoice3Index + (NSSIZE - mVars.ns)) % 0x200;
    }
}
void PCSX::SPU::impl::IrqCheck(MainThreadVariables &mVars) {
    if ((spuCtrl & 0x40))  // some callback and irq active?
    {
        if ((pSpuIrq > mVars.start - 16 &&  // irq address reached?
             pSpuIrq <= mVars.start) ||
            ((mVars.flags & 1) &&  // special: irq on looping addr, when stop/loop flag is set
             (pSpuIrq > mVars.pChannel->pLoop - 16 && pSpuIrq <= mVars.pChannel->pLoop))) {
            mVars.pChannel->data.get<PCSX::SPU::Chan::IrqDone>().value = 1;  // -> debug flag
            scheduleInterrupt();                                             // -> call main emu

            if (settings.get<SPUIRQWait>())  // -> option: wait after irq for main emu
            {
                iSpuAsyncWait = 1;
                mVars.bIRQReturn = 1;
            }
        }
    }
}
void PCSX::SPU::impl::FlagHandler(MainThreadVariables &mVars) {
    if ((mVars.flags & 4) && (!mVars.pChannel->data.get<PCSX::SPU::Chan::IgnoreLoop>().value)) {
        mVars.pChannel->pLoop = mVars.start - 16;  // loop adress
    }
    if (mVars.flags & 1)  // 1: stop/loop
    {
        // We play this block out first...
        // if(!(flags&2))
        // 1+2: do loop... otherwise: stop
        // PETE: if we don't check exactly for 3, loop hang
        // ups will happen (DQ4, for example)
        // and checking if pLoop is set avoids crashes, yeah
        mVars.start = (mVars.flags != 3 || mVars.pChannel->pLoop == NULL) ? (uint8_t *)-1 : mVars.pChannel->pLoop;
    }
}
void PCSX::SPU::impl::FeedStreamData(MainThreadVariables &mVars) {
    // feed the sound
    // wanna have around 1/60 sec (16.666 ms) updates
    if (iCycle++ > 16) {
        bool done = false;
        while (!done) {
            done = m_audioOut.feedStreamData(reinterpret_cast<MiniAudio::Frame *>(pSpuBuffer),
                                             (((uint8_t *)pS) - ((uint8_t *)pSpuBuffer)) / sizeof(MiniAudio::Frame));
            if (bEndThread) {
                bThreadEnded = 1;
                return;
            }
        }
        pS = (int16_t *)pSpuBuffer;
        iCycle = 0;
    }
}
void PCSX::SPU::impl::PMixIrq(MainThreadVariables &mVars) {
    //////////////////////////////////////////////////////
    // special irq handling in the decode buffers (0x0000-0x1000)
    // we know:
    // the decode buffers are located in spu memory in the following way:
    // 0x0000-0x03ff  CD audio left
    // 0x0400-0x07ff  CD audio right
    // 0x0800-0x0bff  Voice 1
    // 0x0c00-0x0fff  Voice 3
    // and decoded data is 16 bit for one sample
    // we assume:
    // even if voices 1/3 are off or no cd audio is playing, the internal
    // play positions will move on and wrap after 0x400 bytes.
    // Therefore: we just need a pointer from spumem+0 to spumem+3ff, and
    // increase this pointer on each sample by 2 bytes. If this pointer
    // (or 0x400 offsets of this pointer) hits the spuirq address, we generate
    // an IRQ. Only problem: the "wait for cpu" option is kinda hard to do here
    // in some of Peops timer modes. So: we ignore this option here (for now).
    // Also note: we abuse the channel 0-3 irq debug display for those irqs
    // (since that's the easiest way to display such irqs in debug mode :))
    // pMixIRQ will only be set, if the config option is active
    for (mVars.ns = 0; mVars.ns < NSSIZE; mVars.ns++) {
        if ((spuCtrl & 0x40) && pSpuIrq && pSpuIrq < spuMemC + 0x1000) {
            for (mVars.ch = 0; mVars.ch < 4; mVars.ch++) {
                if (pSpuIrq >= pMixIrq + (mVars.ch * 0x400) && pSpuIrq < pMixIrq + (mVars.ch * 0x400) + 2) {
                    scheduleInterrupt();
                    s_chan[mVars.ch].data.get<PCSX::SPU::Chan::IrqDone>().value = 1;
                }
            }
        }
        pMixIrq += 2;
        if (pMixIrq > spuMemC + 0x3ff) pMixIrq = spuMemC;
    }
}
void PCSX::SPU::impl::MixAllChannels(MainThreadVariables &mVars) {
    ///////////////////////////////////////////////////////
    // mix all channels (including reverb) into one buffer
    if (settings.get<Mono>())  // no stereo?
    {
        int dl, dr;
        for (mVars.ns = 0; mVars.ns < NSSIZE; mVars.ns++) {
            SSumL[mVars.ns] += MixREVERBLeft(mVars.ns);

            dl = SSumL[mVars.ns] / mVars.voldiv;
            SSumL[mVars.ns] = 0;
            if (dl < -32767) dl = -32767;
            if (dl > 32767) dl = 32767;

            SSumR[mVars.ns] += MixREVERBRight();

            dr = SSumR[mVars.ns] / mVars.voldiv;
            SSumR[mVars.ns] = 0;
            if (dr < -32767) dr = -32767;
            if (dr > 32767) dr = 32767;
            *pS++ = (dl + dr) / 2;
        }
    } else  // stereo:
        for (mVars.ns = 0; mVars.ns < NSSIZE; mVars.ns++) {
            SSumL[mVars.ns] += MixREVERBLeft(mVars.ns);

            mVars.d = SSumL[mVars.ns] / mVars.voldiv;
            SSumL[mVars.ns] = 0;
            if (mVars.d < -32767) mVars.d = -32767;
            if (mVars.d > 32767) mVars.d = 32767;
            *pS++ = mVars.d;

            SSumR[mVars.ns] += MixREVERBRight();

            mVars.d = SSumR[mVars.ns] / mVars.voldiv;
            SSumR[mVars.ns] = 0;
            if (mVars.d < -32767) mVars.d = -32767;
            if (mVars.d > 32767) mVars.d = 32767;
            *pS++ = mVars.d;
        }
}
void PCSX::SPU::impl::writeCaptureBufferCD(int numbSamples) {
    if (pMixIrq) {
        std::unique_lock<std::mutex> lock(cbMtx);
        for (int n = 0; n < numbSamples; n++) {
            if (captureBuffer.startIndex == captureBuffer.endIndex) {
                // If there are no samples left in the temp buffer,
                // we still HAVE to keep writing to the capture buffer.
                spuMem[captureBuffer.currIndex] = 0;
                spuMem[captureBuffer.currIndex + 0x200] = 0;
            } else {
                spuMem[captureBuffer.currIndex] = captureBuffer.CDCapLeft[captureBuffer.startIndex];
                spuMem[captureBuffer.currIndex + 0x200] = captureBuffer.CDCapRight[captureBuffer.startIndex];
                captureBuffer.startIndex = (captureBuffer.startIndex + 1) % CaptureBuffer::CB_SIZE;
            }
            captureBuffer.currIndex = (captureBuffer.currIndex + 1) % 0x200;
        }
        // Update the capture buffer voice index, which in the end, should be the same as
        // tmpCapVoice1Index, tmpCapVoice3Index and captureBuffer.currIndex.
        // Unless I'm missing something in Pete's code.
        /* capBufVoiceIndex = (capBufVoiceIndex + NSSIZE) % 0x200;
        if ((tmpCapVoice1Index != tmpCapVoice3Index) || (tmpCapVoice3Index != captureBuffer.currIndex) ||
            (captureBuffer.currIndex != capBufVoiceIndex))
            g_system->log(LogClass::SPU, "Capture buffer indices are not the same.\n");*/
    }
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// SPU ASYNC... even newer epsxe func
//  1 time every 'cycle' cycles... harhar
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::async(uint32_t cycle) {
    if (iSpuAsyncWait) {
        iSpuAsyncWait++;
        if (iSpuAsyncWait <= 64) return;
        iSpuAsyncWait = 0;
    }
}

////////////////////////////////////////////////////////////////////////
// XA AUDIO
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::playADPCMchannel(xa_decode_t *xap) {
    if (!settings.get<Streaming>()) return;  // no XA? bye
    if (!xap) return;
    if (!xap->freq) return;  // no xa freq ? bye

    FeedXA(xap);  // call main XA feeder
}

////////////////////////////////////////////////////////////////////////
// INIT/EXIT STUFF
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// SPUINIT: this func will be called first by the main emu
////////////////////////////////////////////////////////////////////////

long PCSX::SPU::impl::init(void) {
    spuMemC = (uint8_t *)spuMem;  // just small setup

    wipeChannels();
    return 0;
}

void PCSX::SPU::impl::wipeChannels() {
    for (unsigned i = 0; i < MAXCHAN; i++) {
        s_chan[i].ADSR.reset();
        s_chan[i].ADSRX.reset();
        s_chan[i].data.reset();
        s_chan[i].pCurr = nullptr;
        s_chan[i].pLoop = nullptr;
        s_chan[i].pStart = nullptr;
    }
    memset((void *)&rvb, 0, sizeof(REVERBInfo));
}

////////////////////////////////////////////////////////////////////////
// SETUPTIMER: init of certain buffers and threads/timers
////////////////////////////////////////////////////////////////////////


void PCSX::SPU::impl::SetupThread() {
    memset(SSumR, 0, NSSIZE * sizeof(int));  // init some mixing buffers
    memset(SSumL, 0, NSSIZE * sizeof(int));
    memset(iFMod, 0, NSSIZE * sizeof(int));

    pS = (int16_t *)pSpuBuffer;  // setup soundbuffer pointer

    bEndThread = 0;  // init thread vars
    bThreadEnded = 0;
    bSpuInit = 1;  // flag: we are inited
    hMainThread = std::thread([this]() { MainThread(); });
}

////////////////////////////////////////////////////////////////////////
// REMOVETIMER: kill threads/timers
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::RemoveThread() {
    bEndThread = 1;  // raise flag to end thread

    using namespace std::chrono_literals;
    while (!bThreadEnded) {
        std::this_thread::sleep_for(5ms);
    }  // -> wait till thread has ended
    std::this_thread::sleep_for(5ms);

    hMainThread.join();

    bThreadEnded = 0;  // no more spu is running
    bSpuInit = 0;
}

////////////////////////////////////////////////////////////////////////
// SETUPSTREAMS: init most of the spu buffers
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::SetupStreams() {
    int i;

    pSpuBuffer = (uint8_t *)malloc(32768);  // alloc mixing buffer

    if (settings.get<Reverb>() == 1)
        i = 88200 * 2;
    else
        i = NSSIZE * 2;

    sRVBStart = (int *)malloc(i * 4);  // alloc reverb buffer
    memset(sRVBStart, 0, i * 4);
    sRVBEnd = sRVBStart + i;
    sRVBPlay = sRVBStart;

    for (i = 0; i < MAXCHAN; i++)  // loop sound channels
    {
        // we don't use mutex sync... not needed, would only
        // slow us down:
        //   s_chan[i].hMutex=CreateMutex(NULL,FALSE,NULL);
        s_chan[i].ADSRX.get<exSustainLevel>().value = 0xf << 27;  // -> init sustain
        s_chan[i].data.get<PCSX::SPU::Chan::Mute>().value = false;
        s_chan[i].data.get<PCSX::SPU::Chan::IrqDone>().value = 0;
        s_chan[i].pLoop = spuMemC;
        s_chan[i].pStart = spuMemC;
        s_chan[i].pCurr = spuMemC;
    }
}

////////////////////////////////////////////////////////////////////////
// REMOVESTREAMS: free most buffer
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::RemoveStreams(void) {
    free(pSpuBuffer);  // free mixing buffer
    pSpuBuffer = NULL;
    free(sRVBStart);  // free reverb buffer
    sRVBStart = 0;
}

////////////////////////////////////////////////////////////////////////
// SPUOPEN: called by main emu after init
////////////////////////////////////////////////////////////////////////

bool PCSX::SPU::impl::open() {
    if (bSPUIsOpen) return true;  // security for some stupid main emus

    settings.get<Streaming>() = true;  // just small setup
    settings.get<Volume>() = 3;
    iReverbOff = -1;
    spuIrq = 0;
    spuAddr = 0xffffffff;
    bEndThread = 0;
    bThreadEnded = 0;
    spuMemC = (uint8_t *)spuMem;
    pMixIrq = 0;
    wipeChannels();
    pSpuIrq = 0;
    settings.get<SPUIRQWait>() = true;

    //    ReadConfig();  // read user stuff

    SetupStreams();  // prepare streaming

    SetupThread();  // timer for feeding data

    bSPUIsOpen = 1;

    m_lastUpdated = std::chrono::steady_clock::now();

    resetCaptureBuffer();

    return true;
}

////////////////////////////////////////////////////////////////////////
// SPUCLOSE: called before shutdown
////////////////////////////////////////////////////////////////////////

long PCSX::SPU::impl::close(void) {
    if (!bSPUIsOpen) return 0;  // some security

    bSPUIsOpen = 0;  // no more open

    RemoveThread();   // no more feeding
    RemoveStreams();  // no more streaming

    return 0;
}

////////////////////////////////////////////////////////////////////////
// SPUSHUTDOWN: called by main emu on final exit
////////////////////////////////////////////////////////////////////////

long PCSX::SPU::impl::shutdown(void) { return 0; }

////////////////////////////////////////////////////////////////////////
// SETUP CALLBACKS
// this functions will be called once,
// passes a callback that should be called on SPU-IRQ/cdda volume change
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::registerCDDAVolume(void (*CDDAVcallback)(uint16_t, uint16_t)) { cddavCallback = CDDAVcallback; }

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::playCDDAchannel(int16_t *data, int size) {
    m_cdda.freq = 44100;
    m_cdda.nsamples = size / 4;
    m_cdda.stereo = 1;
    m_cdda.nbits = 16;
    memcpy(m_cdda.pcm, data, size);
    FeedXA(&m_cdda);
}
