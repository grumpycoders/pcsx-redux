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

#include "spu/externals.h"
#include "spu/gauss.h"
#include "spu/interface.h"

static uint16_t loword(uint32_t v) { return v & 0xffff; }
static uint16_t hiword(uint32_t v) { return (v >> 16) & 0xffff; }

void PCSX::SPU::impl::FeedXA(xa_decode_t *xap) {
    int sinc, spos, i, iSize, vl, vr, voldiv = 4 - settings.get<Volume>();

    SDLAudio::Frame XABuffer[32 * 1024];
    SDLAudio::Frame *XAFeed = XABuffer;

    if (!spuIsOpen) return;

    // Store the info for save states.
    xapGlobal = xap;

    // Get the size.
    iSize = ((44100 * xap->nsamples) / xap->freq);
    // Emulation speed no longer scales the XA feed size here. The old Emulator::SettingScaler only ever
    // adjusted this for sub-realtime (its min(100, scaler) meant fast-forward never touched XA at all),
    // and it defaulted to 100 (== no change). XA speed-up now happens at the sink, which drains the XA
    // stream (stream 1) at the same multiplier as the voices stream. Dropping it is a no-op at default.
    // Nothing to feed.
    if (!iSize) return;

    assert(iSize <= 32 * 1024);

    spos = 0x10000L;
    // Calculate the frequency as sample count divided by size.
    sinc = (xap->nsamples << 16) / iSize;

    // The lock is needed for the capture buffers. Open question: should it be taken here or in the inner loop?
    if (mixIrqAddress) cbMtx.lock();

    if (xap->stereo) {
        uint32_t *pS = (uint32_t *)xap->pcm;
        uint32_t l = 0;

        for (i = 0; i < iSize; i++) {
            if (settings.get<Interpolation>() == 2) {
                while (spos >= 0x10000L) {
                    l = *pS++;
                    gauss_window[gauss_ptr] = (int16_t)loword(l);
                    gauss_window[4 + gauss_ptr] = (int16_t)hiword(l);
                    gauss_ptr = (gauss_ptr + 1) & 3;
                    spos -= 0x10000L;
                }
                vl = (spos >> 8) & 0xff;
                vr = (Gauss::gauss512[0x0ff - vl] * gvall0()) >> 15;
                vr += (Gauss::gauss512[0x1ff - vl] * gvall(1)) >> 15;
                vr += (Gauss::gauss512[0x100 + vl] * gvall(2)) >> 15;
                vr += (Gauss::gauss512[0x000 + vl] * gvall(3)) >> 15;
                l = vr & 0xffff;
                vr = (Gauss::gauss512[0x0ff - vl] * gvalr0()) >> 15;
                vr += (Gauss::gauss512[0x1ff - vl] * gvalr(1)) >> 15;
                vr += (Gauss::gauss512[0x100 + vl] * gvalr(2)) >> 15;
                vr += (Gauss::gauss512[0x000 + vl] * gvalr(3)) >> 15;
                l |= vr << 16;
            } else {
                while (spos >= 0x10000L) {
                    l = *pS++;
                    spos -= 0x10000L;
                }
            }

            SDLAudio::Frame f;
            int16_t rawSampleL = static_cast<int16_t>(l & 0xffff);
            int16_t rawSampleR = static_cast<int16_t>(l >> 16);
            if (mixIrqAddress) {
                captureBuffer.CDCapLeft[captureBuffer.endIndex] = (uint16_t)rawSampleL;
                captureBuffer.CDCapRight[captureBuffer.endIndex] = (uint16_t)rawSampleR;
                captureBuffer.endIndex = (captureBuffer.endIndex + 1) % CaptureBuffer::CB_SIZE;
                if (captureBuffer.endIndex == captureBuffer.startIndex) {
                    g_system->log(LogClass::SPU, "Capture buffer is overflowing. Increase CB_SIZE.\n");
                }
            }
            f.L = rawSampleL / voldiv;
            f.R = rawSampleR / voldiv;

            *XAFeed++ = f;
            spos += sinc;
        }
    } else {
        uint16_t *pS = (uint16_t *)xap->pcm;
        uint32_t l;
        int16_t s = 0;

        for (i = 0; i < iSize; i++) {
            if (settings.get<Interpolation>() == 2) {
                while (spos >= 0x10000L) {
                    gauss_window[gauss_ptr] = (int16_t)*pS++;
                    gauss_ptr = (gauss_ptr + 1) & 3;
                    spos -= 0x10000L;
                }
                vl = (spos >> 8) & 0xff;
                vr = (Gauss::gauss512[0x0ff - vl] * gvall0()) >> 15;
                vr += (Gauss::gauss512[0x1ff - vl] * gvall(1)) >> 15;
                vr += (Gauss::gauss512[0x100 + vl] * gvall(2)) >> 15;
                vr += (Gauss::gauss512[0x000 + vl] * gvall(3)) >> 15;
                l = s = vr;
                l &= 0xffff;
            } else {
                while (spos >= 0x10000L) {
                    s = *pS++;
                    spos -= 0x10000L;
                }
                l = s;
            }

            SDLAudio::Frame f;
            int16_t rawSampleL = static_cast<int16_t>(l & 0xffff);
            int16_t rawSampleR = static_cast<int16_t>(l >> 16);
            // Write the CD-XA samples (left/right) to a temporary buffer. Wrap around if necessary.
            if (mixIrqAddress) {
                captureBuffer.CDCapLeft[captureBuffer.endIndex] = (uint16_t)rawSampleL;
                captureBuffer.CDCapRight[captureBuffer.endIndex] = (uint16_t)rawSampleR;
                captureBuffer.endIndex = (captureBuffer.endIndex + 1) % CaptureBuffer::CB_SIZE;
                if (captureBuffer.endIndex == captureBuffer.startIndex) {
                    g_system->log(LogClass::SPU, "Capture buffer is overflowing. Increase CB_SIZE.\n");
                }
            }

            f.L = rawSampleL / voldiv;
            f.R = rawSampleR / voldiv;
            *XAFeed++ = f;
            spos += sinc;
        }
    }
    if (mixIrqAddress) cbMtx.unlock();

    m_audioOut.feedStreamData(reinterpret_cast<SDLAudio::Frame *>(XABuffer), (XAFeed - XABuffer), 1);
}
