/***************************************************************************
                            xa.c  -  description
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
// 2003/02/18 - kode54
// - added gaussian interpolation
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include <algorithm>

#include "spu/externals.h"
#include "spu/gauss.h"
#include "spu/interface.h"

static uint16_t loword(uint32_t v) { return v & 0xffff; }
static uint16_t hiword(uint32_t v) { return (v >> 16) & 0xffff; }

////////////////////////////////////////////////////////////////////////
// FEED XA
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::FeedXA(xa_decode_t *xap) {
    int sinc, spos, i, iSize, iPlace, vl, vr, voldiv = 4 - settings.get<Volume>();

    MiniAudio::Frame XABuffer[32 * 1024];
    MiniAudio::Frame *XAFeed = XABuffer;

    iPlace = 32 * 1024;

    if (!bSPUIsOpen) return;

    xapGlobal = xap;  // store info for save states

    iSize = ((44100 * xap->nsamples) / xap->freq);  // get size
    iSize *= 100;
    iSize /= std::min(100, g_emulator->settings.get<Emulator::SettingScaler>().value);
    if (!iSize) return;  // none? bye

    assert(iSize <= 32 * 1024);

    spos = 0x10000L;
    sinc = (xap->nsamples << 16) / iSize;  // calc freq by num / size

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
                vl = (spos >> 6) & ~3;
                vr = (Gauss::gauss[vl] * gvall0()) & ~2047;
                vr += (Gauss::gauss[vl + 1] * gvall(1)) & ~2047;
                vr += (Gauss::gauss[vl + 2] * gvall(2)) & ~2047;
                vr += (Gauss::gauss[vl + 3] * gvall(3)) & ~2047;
                l = (vr >> 11) & 0xffff;
                vr = (Gauss::gauss[vl] * gvalr0()) & ~2047;
                vr += (Gauss::gauss[vl + 1] * gvalr(1)) & ~2047;
                vr += (Gauss::gauss[vl + 2] * gvalr(2)) & ~2047;
                vr += (Gauss::gauss[vl + 3] * gvalr(3)) & ~2047;
                l |= vr << 5;
            } else {
                while (spos >= 0x10000L) {
                    l = *pS++;
                    spos -= 0x10000L;
                }
            }

            MiniAudio::Frame f;
            f.L = static_cast<int16_t>(l & 0xffff) / voldiv;
            f.R = static_cast<int16_t>(l >> 16) / voldiv;
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
                vl = (spos >> 6) & ~3;
                vr = (Gauss::gauss[vl] * gvall0()) & ~2047;
                vr += (Gauss::gauss[vl + 1] * gvall(1)) & ~2047;
                vr += (Gauss::gauss[vl + 2] * gvall(2)) & ~2047;
                vr += (Gauss::gauss[vl + 3] * gvall(3)) & ~2047;
                l = s = vr >> 11;
                l &= 0xffff;
            } else {
                while (spos >= 0x10000L) {
                    s = *pS++;
                    spos -= 0x10000L;
                }
                l = s;
            }

            MiniAudio::Frame f;
            f.L = static_cast<int16_t>(l) / voldiv;
            f.R = f.L;
            *XAFeed++ = f;
            spos += sinc;
        }
    }

    m_audioOut.feedStreamData(reinterpret_cast<MiniAudio::Frame *>(XABuffer), (XAFeed - XABuffer), 1);
}
