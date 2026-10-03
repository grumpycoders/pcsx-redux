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

#include <algorithm>

#include "core/psxemulator.h"
#include "core/r3000a.h"
#include "spu/externals.h"
#include "spu/interface.h"


// The CD decoder resamples 37.8 kHz to 44.1 kHz by writing each sample into a
// 32-entry ring and, every 6 samples, producing 7 outputs through these zigzag
// tables (psx-spx, "25-point Zigzag Interpolation"). 18.9 kHz audio goes
// through the same path, with the midpoint of each pair of samples inserted.
static const int16_t s_zigzag[7][29] = {
    {0,       0,       0,       0,       0,       -0x0002, 0x000a,  -0x0022, 0x0041,  -0x0054,
     0x0034,  0x0009,  -0x010a, 0x0400,  -0x0a78, 0x234c,  0x6794,  -0x1780, 0x0bcd,  -0x0623,
     0x0350,  -0x016d, 0x006b,  0x000a,  -0x0010, 0x0011,  -0x0008, 0x0003,  -0x0001},
    {0,       0,       0,       -0x0002, 0,       0x0003,  -0x0013, 0x003c,  -0x004b, 0x00a2,
     -0x00e3, 0x0132,  -0x0043, -0x0267, 0x0c9d,  0x74bb,  -0x11b4, 0x09b8,  -0x05bf, 0x0372,
     -0x01a8, 0x00a6,  -0x001b, 0x0005,  0x0006,  -0x0008, 0x0003,  -0x0001, 0},
    {0,       0,       -0x0001, 0x0003,  -0x0002, -0x0005, 0x001f,  -0x004a, 0x00b3,  -0x0192,
     0x02b1,  -0x039e, 0x04f8,  -0x05a6, 0x7939,  -0x05a6, 0x04f8,  -0x039e, 0x02b1,  -0x0192,
     0x00b3,  -0x004a, 0x001f,  -0x0005, -0x0002, 0x0003,  -0x0001, 0,       0},
    {0,       -0x0001, 0x0003,  -0x0008, 0x0006,  0x0005,  -0x001b, 0x00a6,  -0x01a8, 0x0372,
     -0x05bf, 0x09b8,  -0x11b4, 0x74bb,  0x0c9d,  -0x0267, -0x0043, 0x0132,  -0x00e3, 0x00a2,
     -0x004b, 0x003c,  -0x0013, 0x0003,  0,       -0x0002, 0,       0,       0},
    {-0x0001, 0x0003,  -0x0008, 0x0011,  -0x0010, 0x000a,  0x006b,  -0x016d, 0x0350,  -0x0623,
     0x0bcd,  -0x1780, 0x6794,  0x234c,  -0x0a78, 0x0400,  -0x010a, 0x0009,  0x0034,  -0x0054,
     0x0041,  -0x0022, 0x000a,  -0x0001, 0,       0x0001,  0,       0,       0},
    {0x0002,  -0x0008, 0x0010,  -0x0023, 0x002b,  0x001a,  -0x00eb, 0x027b,  -0x0548, 0x0afa,
     -0x16fa, 0x53e0,  0x3c07,  -0x1249, 0x080e,  -0x0347, 0x015b,  -0x0044, -0x0017, 0x0046,
     -0x0023, 0x0011,  -0x0005, 0,       0,       0,       0,       0,       0},
    {-0x0005, 0x0011,  -0x0023, 0x0046,  -0x0017, -0x0044, 0x015b,  -0x0347, 0x080e,  -0x1249,
     0x3c07,  0x53e0,  -0x16fa, 0x0afa,  -0x0548, 0x027b,  -0x00eb, 0x001a,  0x002b,  -0x0023,
     0x0010,  -0x0008, 0x0002,  0,       0,       0,       0,       0,       0},
};

int16_t PCSX::SPU::impl::zigzag(const int16_t *ring, unsigned table) {
    int32_t sum = 0;
    for (unsigned i = 1; i <= 29; i++) {
        sum += (int32_t(ring[(xaRingPos - i) & 0x1f]) * s_zigzag[table][i - 1]) >> 15;
    }
    return std::clamp(sum, int32_t(-0x8000), int32_t(0x7fff));
}

void PCSX::SPU::impl::FeedXA(xa_decode_t *xap) {
    int voldiv = 4 - settings.get<Volume>();

    if (!spuIsOpen) return;

    // Store the info for save states.
    xapGlobal = xap;

    const int repeat = xap->freq == 18900 ? 2 : 1;
    // 6 inputs make 7 outputs; size for the whole sector plus what is pending.
    static constexpr size_t c_maxFrames = (4032 * 2 / 6 + 1) * 7;
    SDLAudio::Frame XABuffer[c_maxFrames];
    SDLAudio::Frame *XAFeed = XABuffer;

    // The lock is needed for the capture buffers and mixIrqAddress, both shared with the
    // mixer thread. Taken unconditionally: gating it on an unlocked read of mixIrqAddress
    // is itself a race, and could pair a skipped lock with a later unlock.
    std::unique_lock<std::mutex> cbLock(cbMtx);
    cdFeedCycle = PCSX::g_emulator->m_cpu->m_regs.cycle;

    if (xap->freq == 44100) {
        // CD-DA is already at the output rate and skips the zigzag interpolator.
        for (int i = 0; i < xap->nsamples; i++) {
            int16_t l = xap->pcm[i * 2];
            int16_t r = xap->pcm[i * 2 + 1];
            if (mixIrqAddress) {
                captureBuffer.CDCapLeft[captureBuffer.endIndex] = (uint16_t)l;
                captureBuffer.CDCapRight[captureBuffer.endIndex] = (uint16_t)r;
                captureBuffer.endIndex = (captureBuffer.endIndex + 1) % CaptureBuffer::CB_SIZE;
                if (captureBuffer.endIndex == captureBuffer.startIndex) {
                    g_system->log(LogClass::SPU, "Capture buffer is overflowing. Increase CB_SIZE.\n");
                }
            }
            SDLAudio::Frame f;
            f.L = l / voldiv;
            f.R = r / voldiv;
            *XAFeed++ = f;
        }
        cbLock.unlock();
        if (XAFeed != XABuffer) {
            m_audioOut.feedStreamData(reinterpret_cast<SDLAudio::Frame *>(XABuffer), (XAFeed - XABuffer), 1);
        }
        return;
    }

    for (int i = 0; i < xap->nsamples; i++) {
        int16_t l, r;
        if (xap->stereo) {
            l = xap->pcm[i * 2];
            r = xap->pcm[i * 2 + 1];
        } else {
            // Mono XA plays on both sides.
            l = r = xap->pcm[i];
        }
        for (int k = 0; k < repeat; k++) {
            int16_t inL = l, inR = r;
            if (repeat == 2 && k == 0) {
                inL = (int32_t(xaLastL) + l) >> 1;
                inR = (int32_t(xaLastR) + r) >> 1;
            }
            xaRingL[xaRingPos & 0x1f] = inL;
            xaRingR[xaRingPos & 0x1f] = inR;
            xaRingPos++;
            if (--xaSixStep > 0) continue;
            xaSixStep = 6;
            for (unsigned t = 0; t < 7; t++) {
                int64_t zl = zigzag(xaRingL, t);
                int64_t zr = zigzag(xaRingR, t);
                // ATV matrix after the interpolator, then 1.026 before the 16-bit clamp and 0.973
                // after it. On a SCPH-7502 the level rises linearly with ATV up to the clamp, and the
                // clamped level sits at 31880, as with CD-DA.
                int outL = std::clamp(int(((zl * xaAtv[0] + zr * xaAtv[3]) * 33617) >> 22), -0x8000, 0x7fff);
                int outR = std::clamp(int(((zr * xaAtv[2] + zl * xaAtv[1]) * 33617) >> 22), -0x8000, 0x7fff);
                int16_t rawSampleL = (outL * 31880) >> 15;
                int16_t rawSampleR = (outR * 31880) >> 15;
                if (mixIrqAddress) {
                    captureBuffer.CDCapLeft[captureBuffer.endIndex] = (uint16_t)rawSampleL;
                    captureBuffer.CDCapRight[captureBuffer.endIndex] = (uint16_t)rawSampleR;
                    captureBuffer.endIndex = (captureBuffer.endIndex + 1) % CaptureBuffer::CB_SIZE;
                    if (captureBuffer.endIndex == captureBuffer.startIndex) {
                        g_system->log(LogClass::SPU, "Capture buffer is overflowing. Increase CB_SIZE.\n");
                    }
                }
                SDLAudio::Frame f;
                f.L = rawSampleL / voldiv;
                f.R = rawSampleR / voldiv;
                *XAFeed++ = f;
            }
        }
        xaLastL = l;
        xaLastR = r;
    }
    cbLock.unlock();

    if (XAFeed != XABuffer) {
        m_audioOut.feedStreamData(reinterpret_cast<SDLAudio::Frame *>(XABuffer), (XAFeed - XABuffer), 1);
    }
}
