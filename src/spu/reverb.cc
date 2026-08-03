/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "spu/reverb.h"

#include <string.h>

#include <algorithm>

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::ReverbUnit::reset() { memset((void *)&rvb, 0, sizeof(REVERBInfo)); }

////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::ReverbUnit::start(SPUCHAN *voice, uint16_t spuCtrl) {
    voice->data.get<Chan::RVBActive>().value =
        voice->data.get<Chan::Reverb>().value && (spuCtrl & kReverbMasterEnable);
}

////////////////////////////////////////////////////////////////////////

// Helper for Neill's reverb: re-initializes the reverb mixing buffer.
void PCSX::SPU::ReverbUnit::init(int nssize) { memset(mixStart, 0, nssize * 2 * 4); }

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::ReverbUnit::store(SPUCHAN *voice, int ns) {
    const int sendLeft = (voice->data.get<Chan::sval>().value * voice->volume.left()) / 0x4000;
    const int sendRight = (voice->data.get<Chan::sval>().value * voice->volume.right()) / 0x4000;

    // Every active reverb voice is summed into the mixing buffer, interleaved.
    ns <<= 1;
    mixStart[ns] += sendLeft;
    mixStart[ns + 1] += sendRight;
}

////////////////////////////////////////////////////////////////////////

// Resolve a work-area offset to a sample index, wrapping at both ends. Offsets
// arrive in 32-bit units, hence the * 4.
int PCSX::SPU::ReverbUnit::wrapOffset(int offset, int extraSample) const {
    offset = offset * 4 + rvb.CurrAddr + extraSample;
    while (offset > 0x3ffff) offset = rvb.StartAddr + (offset - 0x40000);
    while (offset < rvb.StartAddr) offset = 0x3ffff - (rvb.StartAddr - offset);
    return offset;
}

int PCSX::SPU::ReverbUnit::getBuffer(int offset, uint16_t *spuMem) const {
    return reinterpret_cast<int16_t *>(spuMem)[wrapOffset(offset, 0)];
}

template <int ExtraSample>
void PCSX::SPU::ReverbUnit::setBuffer(int offset, int value, uint16_t *spuMem) {
    reinterpret_cast<int16_t *>(spuMem)[wrapOffset(offset, ExtraSample)] =
        static_cast<int16_t>(std::clamp(value, -32768, 32767));
}


////////////////////////////////////////////////////////////////////////
int PCSX::SPU::ReverbUnit::mixLeft(int ns, uint16_t *spuMem, uint16_t spuCtrl) {
    // This function is called at 44.1 kHz.
    static int callCount = 0;

    // Reverb is off.
    if (!rvb.StartAddr) {
        rvb.lastWetLeft = rvb.lastWetRight = rvb.wetLeft = rvb.wetRight = 0;
        return 0;
    }

    callCount++;

    // Work on every second left value: downsample to 22 kHz.
    if (callCount & 1) {
        // Reverb on.
        if (spuCtrl & kReverbMasterEnable) {
            int ACC0, ACC1, FB_A0, FB_A1, FB_B0, FB_B1;

            const int INPUT_SAMPLE_L = *(mixStart + (ns << 1));
            const int INPUT_SAMPLE_R = *(mixStart + (ns << 1) + 1);

            const int IIR_INPUT_A0 = (getBuffer(rvb.IIR_SRC_A0, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
            const int IIR_INPUT_A1 = (getBuffer(rvb.IIR_SRC_A1, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;
            const int IIR_INPUT_B0 = (getBuffer(rvb.IIR_SRC_B0, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
            const int IIR_INPUT_B1 = (getBuffer(rvb.IIR_SRC_B1, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;

            const int IIR_A0 = (IIR_INPUT_A0 * rvb.IIR_ALPHA) / 32768L +
                               (getBuffer(rvb.IIR_DEST_A0, spuMem) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_A1 = (IIR_INPUT_A1 * rvb.IIR_ALPHA) / 32768L +
                               (getBuffer(rvb.IIR_DEST_A1, spuMem) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_B0 = (IIR_INPUT_B0 * rvb.IIR_ALPHA) / 32768L +
                               (getBuffer(rvb.IIR_DEST_B0, spuMem) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_B1 = (IIR_INPUT_B1 * rvb.IIR_ALPHA) / 32768L +
                               (getBuffer(rvb.IIR_DEST_B1, spuMem) * (32768L - rvb.IIR_ALPHA)) / 32768L;

            setBuffer<1>(rvb.IIR_DEST_A0, IIR_A0, spuMem);
            setBuffer<1>(rvb.IIR_DEST_A1, IIR_A1, spuMem);
            setBuffer<1>(rvb.IIR_DEST_B0, IIR_B0, spuMem);
            setBuffer<1>(rvb.IIR_DEST_B1, IIR_B1, spuMem);

            ACC0 = (getBuffer(rvb.ACC_SRC_A0, spuMem) * rvb.ACC_COEF_A) / 32768L +
                   (getBuffer(rvb.ACC_SRC_B0, spuMem) * rvb.ACC_COEF_B) / 32768L +
                   (getBuffer(rvb.ACC_SRC_C0, spuMem) * rvb.ACC_COEF_C) / 32768L +
                   (getBuffer(rvb.ACC_SRC_D0, spuMem) * rvb.ACC_COEF_D) / 32768L;
            ACC1 = (getBuffer(rvb.ACC_SRC_A1, spuMem) * rvb.ACC_COEF_A) / 32768L +
                   (getBuffer(rvb.ACC_SRC_B1, spuMem) * rvb.ACC_COEF_B) / 32768L +
                   (getBuffer(rvb.ACC_SRC_C1, spuMem) * rvb.ACC_COEF_C) / 32768L +
                   (getBuffer(rvb.ACC_SRC_D1, spuMem) * rvb.ACC_COEF_D) / 32768L;

            FB_A0 = getBuffer(rvb.MIX_DEST_A0 - rvb.FB_SRC_A, spuMem);
            FB_A1 = getBuffer(rvb.MIX_DEST_A1 - rvb.FB_SRC_A, spuMem);
            FB_B0 = getBuffer(rvb.MIX_DEST_B0 - rvb.FB_SRC_B, spuMem);
            FB_B1 = getBuffer(rvb.MIX_DEST_B1 - rvb.FB_SRC_B, spuMem);

            setBuffer<0>(rvb.MIX_DEST_A0, ACC0 - (FB_A0 * rvb.FB_ALPHA) / 32768L, spuMem);
            setBuffer<0>(rvb.MIX_DEST_A1, ACC1 - (FB_A1 * rvb.FB_ALPHA) / 32768L, spuMem);

            setBuffer<0>(rvb.MIX_DEST_B0,
                     (rvb.FB_ALPHA * ACC0) / 32768L - (FB_A0 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
                         (FB_B0 * rvb.FB_X) / 32768L,
                     spuMem);
            setBuffer<0>(rvb.MIX_DEST_B1,
                     (rvb.FB_ALPHA * ACC1) / 32768L - (FB_A1 * (int)(rvb.FB_ALPHA ^ 0xFFFF8000)) / 32768L -
                         (FB_B1 * rvb.FB_X) / 32768L,
                     spuMem);

            rvb.lastWetLeft = rvb.wetLeft;
            rvb.lastWetRight = rvb.wetRight;

            rvb.wetLeft = (getBuffer(rvb.MIX_DEST_A0, spuMem) + getBuffer(rvb.MIX_DEST_B0, spuMem)) / 3;
            rvb.wetRight = (getBuffer(rvb.MIX_DEST_A1, spuMem) + getBuffer(rvb.MIX_DEST_B1, spuMem)) / 3;

            rvb.wetLeft = (rvb.wetLeft * rvb.VolLeft) / 0x4000;
            rvb.wetRight = (rvb.wetRight * rvb.VolRight) / 0x4000;

            rvb.CurrAddr++;
            if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;

            return rvb.lastWetLeft + (rvb.wetLeft - rvb.lastWetLeft) / 2;
        }
        // Reverb off.
        else {
            rvb.lastWetLeft = rvb.lastWetRight = rvb.wetLeft = rvb.wetRight = 0;
        }

        rvb.CurrAddr++;
        if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
    }

return rvb.lastWetLeft;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SPU::ReverbUnit::mixRight() {
    // Return the last right wet value, halfway interpolated toward the current one.
    const int sample = rvb.lastWetRight + (rvb.wetRight - rvb.lastWetRight) / 2;
    rvb.lastWetRight = rvb.wetRight;
    return sample;
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
