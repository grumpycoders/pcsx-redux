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

#include "spu/externals.h"
#include "spu/gauss.h"
#include "spu/interface.h"

static uint16_t loword(uint32_t v) { return v & 0xffff; }
static uint16_t hiword(uint32_t v) { return (v >> 16) & 0xffff; }

////////////////////////////////////////////////////////////////////////
// MIX XA
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::MixXA() {
    int ns;

    for (ns = 0; ns < PCSX::SPU::impl::NSSIZE && XAPlay != XAFeed; ns++) {
        XALastVal = *XAPlay++;
        if (XAPlay == XAEnd) XAPlay = XAStart;
        SSumL[ns] += (((int16_t)(XALastVal & 0xffff)) * iLeftXAVol) / 32767;
        SSumR[ns] += (((int16_t)((XALastVal >> 16) & 0xffff)) * iRightXAVol) / 32767;
    }

    if (XAPlay == XAFeed && XARepeat) {
        XARepeat--;
        for (; ns < NSSIZE; ns++) {
            SSumL[ns] += (((int16_t)(XALastVal & 0xffff)) * iLeftXAVol) / 32767;
            SSumR[ns] += (((int16_t)((XALastVal >> 16) & 0xffff)) * iRightXAVol) / 32767;
        }
    }
}

////////////////////////////////////////////////////////////////////////
// FEED XA
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::FeedXA(xa_decode_t *xap) {
    int sinc, spos, i, iSize, iPlace, vl, vr;

    if (!bSPUIsOpen) return;

    xapGlobal = xap;  // store info for save states
    XARepeat = 100;   // set up repeat

    iSize = ((44100 * xap->nsamples) / xap->freq);  // get size
    if (!iSize) return;                             // none? bye

    if (XAFeed < XAPlay)
        iPlace = XAPlay - XAFeed;  // how much space in my buf?
    else
        iPlace = (XAEnd - XAFeed) + (XAPlay - XAStart);

    if (iPlace == 0) return;  // no place at all

    //----------------------------------------------------//
    if (settings.get<StreamingPitch>())  // pitch change option?
    {
        static uint32_t dwLT = 0;
        static uint32_t dwFPS = 0;
        static int iFPSCnt = 0;
        static int iLastSize = 0;
        static uint32_t dwL1 = 0;
        uint32_t dw = SDL_GetTicks(), dw1, dw2;

        iPlace = iSize;

        dwFPS += dw - dwLT;
        iFPSCnt++;

        dwLT = dw;

        if (iFPSCnt >= 10) {
            if (!dwFPS) dwFPS = 1;
            dw1 = 1000000 / dwFPS;
            if (dw1 >= (dwL1 - 100) && dw1 <= (dwL1 + 100))
                dw1 = dwL1;
            else
                dwL1 = dw1;
            dw2 = (xap->freq * 100 / xap->nsamples);
            if ((!dw1) || ((dw2 + 100) >= dw1))
                iLastSize = 0;
            else {
                iLastSize = iSize * dw2 / dw1;
                if (iLastSize > iPlace) iLastSize = iPlace;
                iSize = iLastSize;
            }
            iFPSCnt = 0;
            dwFPS = 0;
        } else {
            if (iLastSize) iSize = iLastSize;
        }
    }
    //----------------------------------------------------//

    spos = 0x10000L;
    sinc = (xap->nsamples << 16) / iSize;  // calc freq by num / size

    if (xap->stereo) {
        uint32_t *pS = (uint32_t *)xap->pcm;
        uint32_t l = 0;

        if (settings.get<StreamingPitch>()) {
            int32_t l1, l2;
            int16_t s;
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

                s = (int16_t)loword(l);
                l1 = s;
                l1 = (l1 * iPlace) / iSize;
                if (l1 < -32767) l1 = -32767;
                if (l1 > 32767) l1 = 32767;
                s = (int16_t)hiword(l);
                l2 = s;
                l2 = (l2 * iPlace) / iSize;
                if (l2 < -32767) l2 = -32767;
                if (l2 > 32767) l2 = 32767;
                l = (l1 & 0xffff) | (l2 << 16);

                *XAFeed++ = l;

                if (XAFeed == XAEnd) XAFeed = XAStart;
                if (XAFeed == XAPlay) {
                    if (XAPlay != XAStart) XAFeed = XAPlay - 1;
                    break;
                }

                spos += sinc;
            }
        } else {
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

                *XAFeed++ = l;

                if (XAFeed == XAEnd) XAFeed = XAStart;
                if (XAFeed == XAPlay) {
                    if (XAPlay != XAStart) XAFeed = XAPlay - 1;
                    break;
                }

                spos += sinc;
            }
        }
    } else {
        uint16_t *pS = (uint16_t *)xap->pcm;
        uint32_t l;
        int16_t s = 0;

        if (settings.get<StreamingPitch>()) {
            int32_t l1;
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
                    l1 = s = vr >> 11;
                    l1 &= 0xffff;
                } else {
                    while (spos >= 0x10000L) {
                        s = *pS++;
                        spos -= 0x10000L;
                    }
                    l1 = s;
                }

                l1 = (l1 * iPlace) / iSize;
                if (l1 < -32767) l1 = -32767;
                if (l1 > 32767) l1 = 32767;
                l = (l1 & 0xffff) | (l1 << 16);
                *XAFeed++ = l;

                if (XAFeed == XAEnd) XAFeed = XAStart;
                if (XAFeed == XAPlay) {
                    if (XAPlay != XAStart) XAFeed = XAPlay - 1;
                    break;
                }

                spos += sinc;
            }
        } else {
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

                *XAFeed++ = (l | (l << 16));

                if (XAFeed == XAEnd) XAFeed = XAStart;
                if (XAFeed == XAPlay) {
                    if (XAPlay != XAStart) XAFeed = XAPlay - 1;
                    break;
                }

                spos += sinc;
            }
        }
    }
}
