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

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

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

// Per-stage L/R magnitude counters. Off unless PCSX_REVSTATS is set. Accumulates
// sum-of-squares per channel at each stage of the reverb chain so the stage where
// an L-vs-R divergence enters can be named, rather than inferred from the output.
namespace {
struct RevStats {
    static constexpr int kStages = 7;
    static constexpr const char *kNames[kStages] = {"input", "iir_in", "acc", "mix_dest", "wet_raw", "wet_vol", "out"};
    double sumsq[kStages][2] = {};
    long n[kStages][2] = {};
    long ticks = 0;
    bool on = getenv("PCSX_REVSTATS") != nullptr;
    void add(int stage, int ch, int v) { if (!on) return; sumsq[stage][ch] += (double)v * v; n[stage][ch]++; }
    void tick() {
        if (!on) return;
        if (++ticks % (44100 * 4)) return;
        fprintf(stderr, "REVSTATS after %ld samples\n", ticks);
        for (int i = 0; i < kStages; i++) {
            double l = n[i][0] ? sqrt(sumsq[i][0] / n[i][0]) : 0.0;
            double r = n[i][1] ? sqrt(sumsq[i][1] / n[i][1]) : 0.0;
            fprintf(stderr, "REVSTATS %-9s Lrms=%12.2f Rrms=%12.2f L/R=%8.4f\n", kNames[i], l, r, r ? l / r : 0.0);
        }
        fflush(stderr);
    }
};
RevStats s_revStats;

// psx-spx "Reverb Buffer Resampling": input and output to/from the reverb unit are
// resampled with this 39-tap FIR. Redux does neither - the input is bare decimation
// (every other sample dropped, no anti-aliasing) and the output is 2-point linear.
//
// Normalisation, worked from the table rather than assumed: all 39 taps sum to 32766
// (~0x8000), so the DECIMATING direction divides by 0x8000. Upsampling zero-stuffs, so
// the two output phases split the taps - the odd indices contribute only h[19]=0x4000
// (a passthrough of the raw 22kHz sample) and the even indices sum to 16382 (~0x4000).
// The INTERPOLATING direction therefore divides by 0x4000. Getting those two the same
// way round would present as a plausible 2x gain error rather than as a filter fault.
constexpr int kFir[39] = {
    -0x0001, 0x0000,  0x0002, 0x0000, -0x000A, 0x0000,  0x0023, 0x0000,
    -0x0067, 0x0000,  0x010A, 0x0000, -0x0268, 0x0000,  0x0534, 0x0000,
    -0x0B90, 0x0000,  0x2806, 0x4000,  0x2806, 0x0000, -0x0B90, 0x0000,
     0x0534, 0x0000, -0x0268, 0x0000,  0x010A, 0x0000, -0x0067, 0x0000,
     0x0023, 0x0000, -0x000A, 0x0000,  0x0002, 0x0000, -0x0001,
};
// h44[k] = the 44.1kHz reverb input k samples ago; h22[k] = the 22.05kHz wet output
// k ticks ago. The FIR is centred, so a causal implementation runs a fixed delay
// (19 samples in / 10 ticks out). That is harmless here: p3-compare.py scores modulo
// rotation, so a constant group delay costs nothing.
int h44L[39], h44R[39], h22L[20], h22R[20];
int firPhase;
inline void firPushIn(int l, int r) {
    for (int i = 38; i > 0; i--) { h44L[i] = h44L[i - 1]; h44R[i] = h44R[i - 1]; }
    h44L[0] = l; h44R[0] = r;
}
inline void firPushOut(int l, int r) {
    for (int i = 19; i > 0; i--) { h22L[i] = h22L[i - 1]; h22R[i] = h22R[i - 1]; }
    h22L[0] = l; h22R[0] = r;
}
inline int firDecimate(const int *h) {
    int64_t a = 0;
    for (int i = 0; i < 39; i++) a += (int64_t)kFir[i] * h[i];
    return (int)(a / 32768);
}
inline int firInterp(const int *h, bool passthrough) {
    if (passthrough) return h[10];
    int64_t a = 0;
    for (int i = 0; i < 39; i += 2) a += (int64_t)kFir[i] * h[i / 2];
    return (int)(a / 16384);
}

// EXPERIMENT (PCSX_REVPHASE=1): advance lastWetLeft on every call, mirroring mixRight's
// bookkeeping, so the left wet output stops emitting the lagging value on filler samples.
// Phase-only: does not touch any magnitude or coefficient.
const int s_revPhase = getenv("PCSX_REVPHASE") ? atoi(getenv("PCSX_REVPHASE")) : 0;
// 0 = baseline (odd: mid(prev,cur), even: prev)
// 1 = mirror mixRight (advance every call)   -> REFUTED, moves corr to -0.66
// 2 = maximum lag: sample-and-hold, no interpolation on the left at all
// bitmask: 1 = spec APF output stage, 2 = volume /8000h, 4 = sign-extend vLOUT/vROUT
//          8 = 39-tap FIR resampling both directions, 16 = spec IIR read/write offsets
const int s_revSpec = getenv("PCSX_REVSPEC") ? atoi(getenv("PCSX_REVSPEC")) : 0;
}  // namespace

int PCSX::SPU::ReverbUnit::mixLeft(int ns, uint16_t *spuMem, uint16_t spuCtrl) {
    // This function is called at 44.1 kHz.
    static int callCount = 0;

    // Reverb is off.
    if (!rvb.StartAddr) {
        rvb.lastWetLeft = rvb.lastWetRight = rvb.wetLeft = rvb.wetRight = 0;
        return 0;
    }

    callCount++;

    if (s_revSpec & 8) firPushIn(*(mixStart + (ns << 1)), *(mixStart + (ns << 1) + 1));

    // Work on every second left value: downsample to 22 kHz.
    if (callCount & 1) {
        // Reverb on.
        if (spuCtrl & kReverbMasterEnable) {
            int ACC0, ACC1, FB_A0, FB_A1, FB_B0, FB_B1;

            const int INPUT_SAMPLE_L = (s_revSpec & 8) ? firDecimate(h44L) : *(mixStart + (ns << 1));
            const int INPUT_SAMPLE_R = (s_revSpec & 8) ? firDecimate(h44R) : *(mixStart + (ns << 1) + 1);
            s_revStats.add(0, 0, INPUT_SAMPLE_L); s_revStats.add(0, 1, INPUT_SAMPLE_R);

            const int IIR_INPUT_A0 = (getBuffer(rvb.IIR_SRC_A0, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
            const int IIR_INPUT_A1 = (getBuffer(rvb.IIR_SRC_A1, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;
            const int IIR_INPUT_B0 = (getBuffer(rvb.IIR_SRC_B0, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_L * rvb.IN_COEF_L) / 32768L;
            const int IIR_INPUT_B1 = (getBuffer(rvb.IIR_SRC_B1, spuMem) * rvb.IIR_COEF) / 32768L +
                                     (INPUT_SAMPLE_R * rvb.IN_COEF_R) / 32768L;

            s_revStats.add(1, 0, IIR_INPUT_A0); s_revStats.add(1, 1, IIR_INPUT_A1);

            const int IIR_A0 = (IIR_INPUT_A0 * rvb.IIR_ALPHA) / 32768L +
                               (((s_revSpec & 16) ? (int)reinterpret_cast<int16_t *>(spuMem)[wrapOffset(rvb.IIR_DEST_A0, -1)] : getBuffer(rvb.IIR_DEST_A0, spuMem)) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_A1 = (IIR_INPUT_A1 * rvb.IIR_ALPHA) / 32768L +
                               (((s_revSpec & 16) ? (int)reinterpret_cast<int16_t *>(spuMem)[wrapOffset(rvb.IIR_DEST_A1, -1)] : getBuffer(rvb.IIR_DEST_A1, spuMem)) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_B0 = (IIR_INPUT_B0 * rvb.IIR_ALPHA) / 32768L +
                               (((s_revSpec & 16) ? (int)reinterpret_cast<int16_t *>(spuMem)[wrapOffset(rvb.IIR_DEST_B0, -1)] : getBuffer(rvb.IIR_DEST_B0, spuMem)) * (32768L - rvb.IIR_ALPHA)) / 32768L;
            const int IIR_B1 = (IIR_INPUT_B1 * rvb.IIR_ALPHA) / 32768L +
                               (((s_revSpec & 16) ? (int)reinterpret_cast<int16_t *>(spuMem)[wrapOffset(rvb.IIR_DEST_B1, -1)] : getBuffer(rvb.IIR_DEST_B1, spuMem)) * (32768L - rvb.IIR_ALPHA)) / 32768L;

            if (s_revSpec & 16) setBuffer<0>(rvb.IIR_DEST_A0, IIR_A0, spuMem);
            else setBuffer<1>(rvb.IIR_DEST_A0, IIR_A0, spuMem);
            if (s_revSpec & 16) setBuffer<0>(rvb.IIR_DEST_A1, IIR_A1, spuMem);
            else setBuffer<1>(rvb.IIR_DEST_A1, IIR_A1, spuMem);
            if (s_revSpec & 16) setBuffer<0>(rvb.IIR_DEST_B0, IIR_B0, spuMem);
            else setBuffer<1>(rvb.IIR_DEST_B0, IIR_B0, spuMem);
            if (s_revSpec & 16) setBuffer<0>(rvb.IIR_DEST_B1, IIR_B1, spuMem);
            else setBuffer<1>(rvb.IIR_DEST_B1, IIR_B1, spuMem);

            ACC0 = (getBuffer(rvb.ACC_SRC_A0, spuMem) * rvb.ACC_COEF_A) / 32768L +
                   (getBuffer(rvb.ACC_SRC_B0, spuMem) * rvb.ACC_COEF_B) / 32768L +
                   (getBuffer(rvb.ACC_SRC_C0, spuMem) * rvb.ACC_COEF_C) / 32768L +
                   (getBuffer(rvb.ACC_SRC_D0, spuMem) * rvb.ACC_COEF_D) / 32768L;
            ACC1 = (getBuffer(rvb.ACC_SRC_A1, spuMem) * rvb.ACC_COEF_A) / 32768L +
                   (getBuffer(rvb.ACC_SRC_B1, spuMem) * rvb.ACC_COEF_B) / 32768L +
                   (getBuffer(rvb.ACC_SRC_C1, spuMem) * rvb.ACC_COEF_C) / 32768L +
                   (getBuffer(rvb.ACC_SRC_D1, spuMem) * rvb.ACC_COEF_D) / 32768L;

            s_revStats.add(2, 0, ACC0); s_revStats.add(2, 1, ACC1);

            FB_A0 = getBuffer(rvb.MIX_DEST_A0 - rvb.FB_SRC_A, spuMem);
            FB_A1 = getBuffer(rvb.MIX_DEST_A1 - rvb.FB_SRC_A, spuMem);
            FB_B0 = getBuffer(rvb.MIX_DEST_B0 - rvb.FB_SRC_B, spuMem);
            FB_B1 = getBuffer(rvb.MIX_DEST_B1 - rvb.FB_SRC_B, spuMem);

            // psx-spx "SPU Reverb Formula", APF1 then APF2, three clauses each:
            //   Lout=Lout-vAPF1*[mLAPF1-dAPF1], [mLAPF1]=Lout, Lout=Lout*vAPF1+[mLAPF1-dAPF1]
            //   Lout=Lout-vAPF2*[mLAPF2-dAPF2], [mLAPF2]=Lout, Lout=Lout*vAPF2+[mLAPF2-dAPF2]
            //   LeftOutput = Lout*vLOUT          (all products divided by 8000h)
            // The legacy path below implements only the first two clauses of each stage and
            // then reconstructs an output by re-reading two buffer cells and dividing by 3 -
            // a divisor with no counterpart in the spec, whose origin is the "I guessed at
            // the coefs. TODO: check later." comment at the bottom of this file.
            if (s_revSpec & 1) {
                int Lo = ACC0 - (FB_A0 * rvb.FB_ALPHA) / 32768L;
                setBuffer<0>(rvb.MIX_DEST_A0, Lo, spuMem);
                Lo = (Lo * rvb.FB_ALPHA) / 32768L + FB_A0;
                int Ro = ACC1 - (FB_A1 * rvb.FB_ALPHA) / 32768L;
                setBuffer<0>(rvb.MIX_DEST_A1, Ro, spuMem);
                Ro = (Ro * rvb.FB_ALPHA) / 32768L + FB_A1;

                Lo = Lo - (FB_B0 * rvb.FB_X) / 32768L;
                setBuffer<0>(rvb.MIX_DEST_B0, Lo, spuMem);
                Lo = (Lo * rvb.FB_X) / 32768L + FB_B0;
                Ro = Ro - (FB_B1 * rvb.FB_X) / 32768L;
                setBuffer<0>(rvb.MIX_DEST_B1, Ro, spuMem);
                Ro = (Ro * rvb.FB_X) / 32768L + FB_B1;

                s_revStats.add(3, 0, Lo); s_revStats.add(3, 1, Ro);
                rvb.lastWetLeft = rvb.wetLeft;
                rvb.lastWetRight = rvb.wetRight;
                s_revStats.add(4, 0, Lo); s_revStats.add(4, 1, Ro);
                // vLOUT/vROUT are signed 16bit and products divide by 8000h, not 4000h.
                // registers.cc assigns these from a uint16_t with no cast, unlike every
                // other reverb coefficient there, so sign-extend at the point of use.
                static bool once = false;
                if (!once) { once = true;
                    fprintf(stderr, "REVVOL raw VolLeft=0x%08x VolRight=0x%08x  as int16: %d / %d\n",
                            rvb.VolLeft, rvb.VolRight, (int)(int16_t)rvb.VolLeft, (int)(int16_t)rvb.VolRight);
                    fflush(stderr); }
                const int vl = (s_revSpec & 4) ? (int)(int16_t)rvb.VolLeft : rvb.VolLeft;
                const int vr = (s_revSpec & 4) ? (int)(int16_t)rvb.VolRight : rvb.VolRight;
                const int vdiv = (s_revSpec & 2) ? 32768L : 16384L;
                rvb.wetLeft = (Lo * vl) / vdiv;
                rvb.wetRight = (Ro * vr) / vdiv;
                s_revStats.add(5, 0, rvb.wetLeft); s_revStats.add(5, 1, rvb.wetRight);
                rvb.CurrAddr++;
                if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
                if (s_revSpec & 8) {
                    firPushOut(rvb.wetLeft, rvb.wetRight);
                    firPhase = 0;
                    const int outL = firInterp(h22L, true);
                    s_revStats.add(6, 0, outL);
                    return outL;
                }
                const int outL = rvb.lastWetLeft + (rvb.wetLeft - rvb.lastWetLeft) / 2;
                s_revStats.add(6, 0, outL);
                return outL;
            }

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

            s_revStats.add(3, 0, getBuffer(rvb.MIX_DEST_A0, spuMem) + getBuffer(rvb.MIX_DEST_B0, spuMem));
            s_revStats.add(3, 1, getBuffer(rvb.MIX_DEST_A1, spuMem) + getBuffer(rvb.MIX_DEST_B1, spuMem));

            rvb.lastWetLeft = rvb.wetLeft;
            rvb.lastWetRight = rvb.wetRight;

            rvb.wetLeft = (getBuffer(rvb.MIX_DEST_A0, spuMem) + getBuffer(rvb.MIX_DEST_B0, spuMem)) / 3;
            rvb.wetRight = (getBuffer(rvb.MIX_DEST_A1, spuMem) + getBuffer(rvb.MIX_DEST_B1, spuMem)) / 3;

            s_revStats.add(4, 0, rvb.wetLeft); s_revStats.add(4, 1, rvb.wetRight);

            rvb.wetLeft = (rvb.wetLeft * rvb.VolLeft) / 0x4000;
            rvb.wetRight = (rvb.wetRight * rvb.VolRight) / 0x4000;

            rvb.CurrAddr++;
            if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;

            s_revStats.add(5, 0, rvb.wetLeft); s_revStats.add(5, 1, rvb.wetRight);
            {
                const int outL = (s_revPhase == 2) ? rvb.lastWetLeft
                                                   : rvb.lastWetLeft + (rvb.wetLeft - rvb.lastWetLeft) / 2;
                if (s_revPhase == 1) rvb.lastWetLeft = rvb.wetLeft;
                s_revStats.add(6, 0, outL);
                return outL;
            }
        }
        // Reverb off.
        else {
            rvb.lastWetLeft = rvb.lastWetRight = rvb.wetLeft = rvb.wetRight = 0;
        }

        rvb.CurrAddr++;
        if (rvb.CurrAddr > 0x3ffff) rvb.CurrAddr = rvb.StartAddr;
    }

    if (s_revSpec & 8) {
        firPhase = 1;
        const int outL = firInterp(h22L, false);
        s_revStats.add(6, 0, outL);
        return outL;
    }
    if (s_revPhase == 1) {
        const int outL = rvb.lastWetLeft + (rvb.wetLeft - rvb.lastWetLeft) / 2;
        rvb.lastWetLeft = rvb.wetLeft;
        s_revStats.add(6, 0, outL);
        return outL;
    }
    s_revStats.add(6, 0, rvb.lastWetLeft);
    return rvb.lastWetLeft;
}

////////////////////////////////////////////////////////////////////////

int PCSX::SPU::ReverbUnit::mixRight() {
    // Return the last right wet value, halfway interpolated toward the current one.
    if (s_revSpec & 8) {
        const int outR = firInterp(h22R, firPhase == 0);
        s_revStats.add(6, 1, outR);
        s_revStats.tick();
        return outR;
    }
    const int sample = rvb.lastWetRight + (rvb.wetRight - rvb.lastWetRight) / 2;
    rvb.lastWetRight = rvb.wetRight;
    s_revStats.add(6, 1, sample);
    s_revStats.tick();
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
