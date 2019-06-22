/***************************************************************************
                          reverb.c  -  description
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
// 2003/01/19 - Pete
// - added Neill's reverb (see at the end of file)
//
// 2002/12/26 - Pete
// - adjusted reverb handling
//
// 2002/08/14 - Pete
// - added extra reverb
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "spu/externals.h"
#include "spu/interface.h"

////////////////////////////////////////////////////////////////////////
// SET REVERB
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::SetREVERB(unsigned short val) {
    switch (val) {
        case 0x0000:
            iReverbOff = -1;
            break;  // off
        case 0x007D:
            iReverbOff = 32;
            iReverbNum = 2;
            iReverbRepeat = 128;
            break;  // ok room

        case 0x0033:
            iReverbOff = 32;
            iReverbNum = 2;
            iReverbRepeat = 64;
            break;  // studio small
        case 0x00B1:
            iReverbOff = 48;
            iReverbNum = 2;
            iReverbRepeat = 96;
            break;  // ok studio medium
        case 0x00E3:
            iReverbOff = 64;
            iReverbNum = 2;
            iReverbRepeat = 128;
            break;  // ok studio large ok

        case 0x01A5:
            iReverbOff = 128;
            iReverbNum = 4;
            iReverbRepeat = 32;
            break;  // ok hall
        case 0x033D:
            iReverbOff = 256;
            iReverbNum = 4;
            iReverbRepeat = 64;
            break;  // space echo
        case 0x0001:
            iReverbOff = 184;
            iReverbNum = 3;
            iReverbRepeat = 128;
            break;  // echo/delay
        case 0x0017:
            iReverbOff = 128;
            iReverbNum = 2;
            iReverbRepeat = 128;
            break;  // half echo
        default:
            iReverbOff = 32;
            iReverbNum = 1;
            iReverbRepeat = 0;
            break;
    }
}

////////////////////////////////////////////////////////////////////////
// START REVERB
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::StartREVERB(SPUCHAN *pChannel) {
    if (pChannel->data.get<Chan::Reverb>().value && (spuCtrl & 0x80))  // reverb possible?
    {
        if (settings.get<Reverb>() == 2)
            pChannel->data.get<Chan::RVBActive>().value = true;
        else if (settings.get<Reverb>() == 1 && iReverbOff > 0)  // -> fake reverb used?
        {
            pChannel->data.get<Chan::RVBActive>().value = true;  // -> activate it
            pChannel->data.get<Chan::RVBOffset>().value = iReverbOff * 45;
            pChannel->data.get<Chan::RVBRepeat>().value = iReverbRepeat * 45;
            pChannel->data.get<Chan::RVBNum>().value = iReverbNum;
        }
    } else
        pChannel->data.get<Chan::RVBActive>().value = false;  // else -> no reverb
}

////////////////////////////////////////////////////////////////////////
// HELPER FOR NEILL'S REVERB: re-inits our reverb mixing buf
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::InitREVERB() {
    if (settings.get<Reverb>() == 2) {
        memset(sRVBStart, 0, NSSIZE * 2 * 4);
    }
}

////////////////////////////////////////////////////////////////////////
// STORE REVERB
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::StoreREVERB(SPUCHAN *pChannel, int ns) {
    if (settings.get<Reverb>() == 0)
        return;
    else if (settings.get<Reverb>() == 2)  // -------------------------------- // Neil's reverb
    {
        const int iRxl =
            (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::LeftVolume>().value) / 0x4000;
        const int iRxr =
            (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::RightVolume>().value) / 0x4000;

        ns <<= 1;

        *(sRVBStart + ns) += iRxl;  // -> we mix all active reverb channels into an extra buffer
        *(sRVBStart + ns + 1) += iRxr;
    } else  // --------------------------------------------- // Pete's easy fake reverb
    {
        int *pN;
        int iRn, iRr = 0;

        // we use the half channel volume (/0x8000) for the first reverb effects, quarter for next and so on

        int iRxl = (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::LeftVolume>().value) / 0x8000;
        int iRxr = (pChannel->data.get<Chan::sval>().value * pChannel->data.get<Chan::RightVolume>().value) / 0x8000;

        for (iRn = 1; iRn <= pChannel->data.get<Chan::RVBNum>().value;
             iRn++, iRr += pChannel->data.get<Chan::RVBRepeat>().value, iRxl /= 2, iRxr /= 2) {
            pN = sRVBPlay + ((pChannel->data.get<Chan::RVBOffset>().value + iRr + ns) << 1);
            if (pN >= sRVBEnd) pN = sRVBStart + (pN - sRVBEnd);

            (*pN) += iRxl;
            pN++;
            (*pN) += iRxr;
        }
    }
}

////////////////////////////////////////////////////////////////////////

inline int PCSX::SPU::impl::g_buffer(int iOff)  // get_buffer content helper: takes care about wraps
{
    short *p = (short *)spuMem;
    iOff = (iOff * 4) + rvb.CurrAddr;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    return (int)*(p + iOff);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::s_buffer(int iOff,
                                      int iVal)  // set_buffer content helper: takes care about wraps and clipping
{
    short *p = (short *)spuMem;
    iOff = (iOff * 4) + rvb.CurrAddr;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    if (iVal < -32768L) iVal = -32768L;
    if (iVal > 32767L) iVal = 32767L;
    *(p + iOff) = (short)iVal;
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::s_buffer1(
    int iOff, int iVal)  // set_buffer (+1 sample) content helper: takes care about wraps and clipping
{
    short *p = (short *)spuMem;
    iOff = (iOff * 4) + rvb.CurrAddr + 1;
    while (iOff > 0x3FFFF) iOff = rvb.StartAddr + (iOff - 0x40000);
    while (iOff < rvb.StartAddr) iOff = 0x3ffff - (rvb.StartAddr - iOff);
    if (iVal < -32768L) iVal = -32768L;
    if (iVal > 32767L) iVal = 32767L;
    *(p + iOff) = (short)iVal;
}

////////////////////////////////////////////////////////////////////////
int PCSX::SPU::impl::MixREVERBLeft(int ns) {
    if (settings.get<Reverb>() == 0)
        return 0;
    else if (settings.get<Reverb>() == 2) {
        static int iCnt = 0;  // this func will be called with 44.1 khz

        if (!rvb.StartAddr)  // reverb is off
        {
            rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
            return 0;
        }

        iCnt++;

        if (iCnt & 1)  // we work on every second left value: downsample to 22 khz
        {
            if (spuCtrl & 0x80)  // -> reverb on? oki
            {
                int ACC0, ACC1, FB_A0, FB_A1, FB_B0, FB_B1;

                const int INPUT_SAMPLE_L = *(sRVBStart + (ns << 1));
                const int INPUT_SAMPLE_R = *(sRVBStart + (ns << 1) + 1);

                const int IIR_INPUT_A0 =
                    (g_buffer(rvb.IIR_SRC_A0) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
                const int IIR_INPUT_A1 =
                    (g_buffer(rvb.IIR_SRC_A1) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;
                const int IIR_INPUT_B0 =
                    (g_buffer(rvb.IIR_SRC_B0) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
                const int IIR_INPUT_B1 =
                    (g_buffer(rvb.IIR_SRC_B1) * rvb.IIR_COEF) / 32768L + (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;

                const int IIR_A0 = (IIR_INPUT_A0 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_A0) * (32768L - rvb.IIR_ALPHA)) / 32768L;
                const int IIR_A1 = (IIR_INPUT_A1 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_A1) * (32768L - rvb.IIR_ALPHA)) / 32768L;
                const int IIR_B0 = (IIR_INPUT_B0 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_B0) * (32768L - rvb.IIR_ALPHA)) / 32768L;
                const int IIR_B1 = (IIR_INPUT_B1 * rvb.IIR_ALPHA) / 32768L +
                                   (g_buffer(rvb.IIR_DEST_B1) * (32768L - rvb.IIR_ALPHA)) / 32768L;

                s_buffer1(rvb.IIR_DEST_A0, IIR_A0);
                s_buffer1(rvb.IIR_DEST_A1, IIR_A1);
                s_buffer1(rvb.IIR_DEST_B0, IIR_B0);
                s_buffer1(rvb.IIR_DEST_B1, IIR_B1);

                ACC0 = (g_buffer(rvb.ACC_SRC_A0) * rvb.ACC_COEF_A) / 32768L +
                       (g_buffer(rvb.ACC_SRC_B0) * rvb.ACC_COEF_B) / 32768L +
                       (g_buffer(rvb.ACC_SRC_C0) * rvb.ACC_COEF_C) / 32768L +
                       (g_buffer(rvb.ACC_SRC_D0) * rvb.ACC_COEF_D) / 32768L;
                ACC1 = (g_buffer(rvb.ACC_SRC_A1) * rvb.ACC_COEF_A) / 32768L +
                       (g_buffer(rvb.ACC_SRC_B1) * rvb.ACC_COEF_B) / 32768L +
                       (g_buffer(rvb.ACC_SRC_C1) * rvb.ACC_COEF_C) / 32768L +
                       (g_buffer(rvb.ACC_SRC_D1) * rvb.ACC_COEF_D) / 32768L;

                FB_A0 = g_buffer(rvb.MIX_DEST_A0 - rvb.FB_SRC_A);
                FB_A1 = g_buffer(rvb.MIX_DEST_A1 - rvb.FB_SRC_A);
                FB_B0 = g_buffer(rvb.MIX_DEST_B0 - rvb.FB_SRC_B);
                FB_B1 = g_buffer(rvb.MIX_DEST_B1 - rvb.FB_SRC_B);

                s_buffer(rvb.MIX_DEST_A0, ACC0 - (FB_A0 * rvb.FB_ALPHA) / 32768L);
                s_buffer(rvb.MIX_DEST_A1, ACC1 - (FB_A1 * rvb.FB_ALPHA) / 32768L);

                s_buffer(rvb.MIX_DEST_B0, (rvb.FB_ALPHA * ACC0) / 32768L -
                                              (FB_A0 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
                                              (FB_B0 * rvb.FB_X) / 32768L);
                s_buffer(rvb.MIX_DEST_B1, (rvb.FB_ALPHA * ACC1) / 32768L -
                                              (FB_A1 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
                                              (FB_B1 * rvb.FB_X) / 32768L);

                rvb.iLastRVBLeft = rvb.iRVBLeft;
                rvb.iLastRVBRight = rvb.iRVBRight;

                rvb.iRVBLeft = (g_buffer(rvb.MIX_DEST_A0) + g_buffer(rvb.MIX_DEST_B0)) / 3;
                rvb.iRVBRight = (g_buffer(rvb.MIX_DEST_A1) + g_buffer(rvb.MIX_DEST_B1)) / 3;

                rvb.iRVBLeft = (rvb.iRVBLeft * rvb.VolLeft) / 0x4000;
                rvb.iRVBRight = (rvb.iRVBRight * rvb.VolRight) / 0x4000;

                rvb.CurrAddr++;
                if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;

                return rvb.iLastRVBLeft + (rvb.iRVBLeft - rvb.iLastRVBLeft) / 2;
            } else  // -> reverb off
            {
                rvb.iLastRVBLeft = rvb.iLastRVBRight = rvb.iRVBLeft = rvb.iRVBRight = 0;
            }

            rvb.CurrAddr++;
            if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
        }

        return rvb.iLastRVBLeft;
    } else  // easy fake reverb:
    {
        const int iRV = *sRVBPlay;                      // -> simply take the reverb mix buf value
        *sRVBPlay++ = 0;                                // -> init it after
        if (sRVBPlay >= sRVBEnd) sRVBPlay = sRVBStart;  // -> and take care about wrap arounds
        return iRV;                                     // -> return reverb mix buf val
    }
}

////////////////////////////////////////////////////////////////////////

int PCSX::SPU::impl::MixREVERBRight() {
    if (settings.get<Reverb>() == 0)
        return 0;
    else if (settings.get<Reverb>() == 2)  // Neill's reverb:
    {
        int i = rvb.iLastRVBRight + (rvb.iRVBRight - rvb.iLastRVBRight) / 2;
        rvb.iLastRVBRight = rvb.iRVBRight;
        return i;  // -> just return the last right reverb val (little bit scaled by the previous right val)
    } else         // easy fake reverb:
    {
        const int iRV = *sRVBPlay;                      // -> simply take the reverb mix buf value
        *sRVBPlay++ = 0;                                // -> init it after
        if (sRVBPlay >= sRVBEnd) sRVBPlay = sRVBStart;  // -> and take care about wrap arounds
        return iRV;                                     // -> return reverb mix buf val
    }
}

////////////////////////////////////////////////////////////////////////

/*
-----------------------------------------------------------------------------
PSX reverb hardware notes
by Neill Corlett
-----------------------------------------------------------------------------

Yadda yadda disclaimer yadda probably not perfect yadda well it's okay anyway
yadda yadda.

-----------------------------------------------------------------------------

Basics
------

- The reverb buffer is 22khz 16-bit mono PCM.
- It starts at the reverb address given by 1DA2, extends to
  the end of sound RAM, and wraps back to the 1DA2 address.

Setting the address at 1DA2 resets the current reverb work address.

This work address ALWAYS increments every 1/22050 sec., regardless of
whether reverb is enabled (bit 7 of 1DAA set).

And the contents of the reverb buffer ALWAYS play, scaled by the
"reverberation depth left/right" volumes (1D84/1D86).
(which, by the way, appear to be scaled so 3FFF=approx. 1.0, 4000=-1.0)

-----------------------------------------------------------------------------

Register names
--------------

These are probably not their real names.
These are probably not even correct names.
We will use them anyway, because we can.

1DC0: FB_SRC_A       (offset)
1DC2: FB_SRC_B       (offset)
1DC4: IIR_ALPHA      (coef.)
1DC6: ACC_COEF_A     (coef.)
1DC8: ACC_COEF_B     (coef.)
1DCA: ACC_COEF_C     (coef.)
1DCC: ACC_COEF_D     (coef.)
1DCE: IIR_COEF       (coef.)
1DD0: FB_ALPHA       (coef.)
1DD2: FB_X           (coef.)
1DD4: IIR_DEST_A0    (offset)
1DD6: IIR_DEST_A1    (offset)
1DD8: ACC_SRC_A0     (offset)
1DDA: ACC_SRC_A1     (offset)
1DDC: ACC_SRC_B0     (offset)
1DDE: ACC_SRC_B1     (offset)
1DE0: IIR_SRC_A0     (offset)
1DE2: IIR_SRC_A1     (offset)
1DE4: IIR_DEST_B0    (offset)
1DE6: IIR_DEST_B1    (offset)
1DE8: ACC_SRC_C0     (offset)
1DEA: ACC_SRC_C1     (offset)
1DEC: ACC_SRC_D0     (offset)
1DEE: ACC_SRC_D1     (offset)
1DF0: IIR_SRC_B1     (offset)
1DF2: IIR_SRC_B0     (offset)
1DF4: MIX_DEST_A0    (offset)
1DF6: MIX_DEST_A1    (offset)
1DF8: MIX_DEST_B0    (offset)
1DFA: MIX_DEST_B1    (offset)
1DFC: IN_COEF_L      (coef.)
1DFE: IN_COEF_R      (coef.)

The coefficients are signed fractional values.
-32768 would be -1.0
 32768 would be  1.0 (if it were possible... the highest is of course 32767)

The offsets are (byte/8) offsets into the reverb buffer.
i.e. you multiply them by 8, you get byte offsets.
You can also think of them as (samples/4) offsets.
They appear to be signed.  They can be negative.
None of the documented presets make them negative, though.

Yes, 1DF0 and 1DF2 appear to be backwards.  Not a typo.

-----------------------------------------------------------------------------

What it does
------------

We take all reverb sources:
- regular channels that have the reverb bit on
- cd and external sources, if their reverb bits are on
and mix them into one stereo 44100hz signal.

Lowpass/downsample that to 22050hz.  The PSX uses a proper bandlimiting
algorithm here, but I haven't figured out the hysterically exact specifics.
I use an 8-tap filter with these coefficients, which are nice but probably
not the real ones:

0.037828187894
0.157538631280
0.321159685278
0.449322115345
0.449322115345
0.321159685278
0.157538631280
0.037828187894

So we have two input samples (INPUT_SAMPLE_L, INPUT_SAMPLE_R) every 22050hz.

* IN MY EMULATION, I divide these by 2 to make it clip less.
  (and of course the L/R output coefficients are adjusted to compensate)
  The real thing appears to not do this.

At every 22050hz tick:
- If the reverb bit is enabled (bit 7 of 1DAA), execute the reverb
  steady-state algorithm described below
- AFTERWARDS, retrieve the "wet out" L and R samples from the reverb buffer
  (This part may not be exactly right and I guessed at the coefs. TODO: check later.)
  L is: 0.333 * (buffer[MIX_DEST_A0] + buffer[MIX_DEST_B0])
  R is: 0.333 * (buffer[MIX_DEST_A1] + buffer[MIX_DEST_B1])
- Advance the current buffer position by 1 sample

The wet out L and R are then upsampled to 44100hz and played at the
"reverberation depth left/right" (1D84/1D86) volume, independent of the main
volume.

-----------------------------------------------------------------------------

Reverb steady-state
-------------------

The reverb steady-state algorithm is fairly clever, and of course by
"clever" I mean "batshit insane".

buffer[x] is relative to the current buffer position, not the beginning of
the buffer.  Note that all buffer offsets must wrap around so they're
contained within the reverb work area.

Clipping is performed at the end... maybe also sooner, but definitely at
the end.

IIR_INPUT_A0 = buffer[IIR_SRC_A0] * IIR_COEF + INPUT_SAMPLE_L * IN_COEF_L;
IIR_INPUT_A1 = buffer[IIR_SRC_A1] * IIR_COEF + INPUT_SAMPLE_R * IN_COEF_R;
IIR_INPUT_B0 = buffer[IIR_SRC_B0] * IIR_COEF + INPUT_SAMPLE_L * IN_COEF_L;
IIR_INPUT_B1 = buffer[IIR_SRC_B1] * IIR_COEF + INPUT_SAMPLE_R * IN_COEF_R;

IIR_A0 = IIR_INPUT_A0 * IIR_ALPHA + buffer[IIR_DEST_A0] * (1.0 - IIR_ALPHA);
IIR_A1 = IIR_INPUT_A1 * IIR_ALPHA + buffer[IIR_DEST_A1] * (1.0 - IIR_ALPHA);
IIR_B0 = IIR_INPUT_B0 * IIR_ALPHA + buffer[IIR_DEST_B0] * (1.0 - IIR_ALPHA);
IIR_B1 = IIR_INPUT_B1 * IIR_ALPHA + buffer[IIR_DEST_B1] * (1.0 - IIR_ALPHA);

buffer[IIR_DEST_A0 + 1sample] = IIR_A0;
buffer[IIR_DEST_A1 + 1sample] = IIR_A1;
buffer[IIR_DEST_B0 + 1sample] = IIR_B0;
buffer[IIR_DEST_B1 + 1sample] = IIR_B1;

ACC0 = buffer[ACC_SRC_A0] * ACC_COEF_A +
       buffer[ACC_SRC_B0] * ACC_COEF_B +
       buffer[ACC_SRC_C0] * ACC_COEF_C +
       buffer[ACC_SRC_D0] * ACC_COEF_D;
ACC1 = buffer[ACC_SRC_A1] * ACC_COEF_A +
       buffer[ACC_SRC_B1] * ACC_COEF_B +
       buffer[ACC_SRC_C1] * ACC_COEF_C +
       buffer[ACC_SRC_D1] * ACC_COEF_D;

FB_A0 = buffer[MIX_DEST_A0 - FB_SRC_A];
FB_A1 = buffer[MIX_DEST_A1 - FB_SRC_A];
FB_B0 = buffer[MIX_DEST_B0 - FB_SRC_B];
FB_B1 = buffer[MIX_DEST_B1 - FB_SRC_B];

buffer[MIX_DEST_A0] = ACC0 - FB_A0 * FB_ALPHA;
buffer[MIX_DEST_A1] = ACC1 - FB_A1 * FB_ALPHA;
buffer[MIX_DEST_B0] = (FB_ALPHA * ACC0) - FB_A0 * (FB_ALPHA^0x8000) - FB_B0 * FB_X;
buffer[MIX_DEST_B1] = (FB_ALPHA * ACC1) - FB_A1 * (FB_ALPHA^0x8000) - FB_B1 * FB_X;

-----------------------------------------------------------------------------
*/
