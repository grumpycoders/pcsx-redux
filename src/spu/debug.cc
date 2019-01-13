/***************************************************************************
                           debug.c  -  description
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
// 2004/09/18 - Pete
// - corrected ADSRX value display
//
// 2003/01/06 - Pete
// - added Neil's ADSR timings
//
// 2002/05/15 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include "stdafx.h"

#define _IN_DEBUG

#include "externals.h"

////////////////////////////////////////////////////////////////////////
// WINDOWS DEBUG DIALOG HANDLING
////////////////////////////////////////////////////////////////////////

#ifdef _WIN32

#include "resource.h"

//#define SMALLDEBUG
//#include <dbgout.h>

////////////////////////////////////////////////////////////////////////
// display debug infos

const COLORREF crStreamCol[] = {RGB(0, 0, 0),   RGB(255, 255, 255), RGB(128, 0, 128),
                                RGB(0, 128, 0), RGB(0, 0, 255),     RGB(255, 0, 0)};

const COLORREF crAdsrCol[] = {
    RGB(0, 0, 0), RGB(255, 0, 0), RGB(0, 255, 0), RGB(255, 0, 255), RGB(0, 0, 255), RGB(0, 0, 0),
};

HBRUSH hBStream[6];   // brushes for stream lines
HPEN hPAdsr[6];       // pens for adsr lines
int iSelChannel = 0;  // user selected channel

////////////////////////////////////////////////////////////////////////
// display the sound data waves: no subclassing used, so the
// area will not be redrawn... but faster that way, and good enuff
// for debugging purposes

void DisplayStreamInfos(HWND hW) {
    HWND hWS = GetDlgItem(hW, IDC_SAREA);
    HDC hdc;
    RECT r;
    HBRUSH hBO;
    int ch, dy, i, j, id;

    //----------------------------------------------------//

    GetClientRect(hWS, &r);                    // get size of stream display
    hdc = GetDC(hWS);                          // device context
    r.right--;                                 // leave the right border intact
    ScrollDC(hdc, -1, 0, &r, &r, NULL, NULL);  // scroll one pixel to the left

    //----------------------------------------------------//

    hBO = (HBRUSH)SelectObject(hdc, hBStream[0]);  // clean the right border
    PatBlt(hdc, r.right - 1, 0, 1, r.bottom, PATCOPY);

    //----------------------------------------------------//

    dy = r.bottom / MAXCHAN;  // size of one channel area

    for (ch = 0; ch < MAXCHAN; ch++)  // loop the channels
    {
        if (s_chan[ch].bOn)  // channel is on?
        {
            if (s_chan[ch].iIrqDone) {
                s_chan[ch].iIrqDone = 0;
                PatBlt(hdc, r.right - 1, ch * r.bottom / MAXCHAN, 1, dy, BLACKNESS);
                continue;
            }

            j = s_chan[ch].sval;
            if (j < 0) j = -j;  // -> get one channel data (-32k ... 32k)
            j = (dy * j) / 32768;
            if (j == 0) j = 1;                                 // -> adjust to display coords
            i = (dy / 2) + (ch * r.bottom / MAXCHAN) - j / 2;  // -> position where to paint it

            if (s_chan[ch].iMute)
                id = 1;  // -> get color id
            else if (s_chan[ch].bNoise)
                id = 2;
            else if (s_chan[ch].bFMod == 2)
                id = 3;
            else if (s_chan[ch].bFMod == 1)
                id = 4;
            else
                id = 5;

            SelectObject(hdc, hBStream[id]);             // -> select the brush
            PatBlt(hdc, r.right - 1, i, 1, j, PATCOPY);  // -> paint the value line
        }

        if (ch)
            SetPixel(hdc, r.right - 1,                        // -> not first line?
                     ch * r.bottom / MAXCHAN, RGB(0, 0, 0));  // --> draw the line (one dot scrolled to the left)
    }

    //----------------------------------------------------//

    SelectObject(hdc, hBO);  // repair brush

    ReleaseDC(hWS, hdc);  // release context
}

////////////////////////////////////////////////////////////////////////
// display adsr lines: also no subclassing for repainting used

void DisplayADSRInfos(HWND hW) {
    HWND hWS = GetDlgItem(hW, IDC_ADSR);
    HDC hdc;
    RECT r;
    HBRUSH hBO;
    char szB[16];
    int ch = iSelChannel, dx, dy, dm, dn, ia, id, is, ir;

    //----------------------------------------------------// get display size

    GetClientRect(hWS, &r);
    hdc = GetDC(hWS);

    //----------------------------------------------------// clean the area

    hBO = (HBRUSH)SelectObject(hdc, hBStream[0]);
    PatBlt(hdc, 0, 0, r.right, r.bottom, PATCOPY);
    r.left++;
    r.right -= 2;
    r.top++;
    r.bottom -= 2;  // shrink the display rect for better optics

    //----------------------------------------------------//

    ia = min(s_chan[ch].ADSR.AttackTime, 10000);  // get adsr, but limit it for drawing
    id = min(s_chan[ch].ADSR.DecayTime, 10000);
    is = min(s_chan[ch].ADSR.SustainTime, 10000);
    ir = min(s_chan[ch].ADSR.ReleaseTime, 10000);

    dx = ia + id + is + ir;  // get the dx in (limited) adsr units

    // set the real values to the info statics
    SetDlgItemInt(hW, IDC_SADSR1, s_chan[ch].ADSRX.AttackRate ^ 0x7f, FALSE);
    SetDlgItemInt(hW, IDC_SADSR2, (s_chan[ch].ADSRX.DecayRate ^ 0x1f) / 4, FALSE);
    SetDlgItemInt(hW, IDC_SADSR3, s_chan[ch].ADSRX.SustainRate ^ 0x7f, FALSE);
    SetDlgItemInt(hW, IDC_SADSR4, (s_chan[ch].ADSRX.ReleaseRate ^ 0x1f) / 4, FALSE);
    SetDlgItemInt(hW, IDC_SADSR5, s_chan[ch].ADSRX.SustainLevel >> 27, FALSE);

    SetDlgItemInt(hW, IDC_SADSR6, s_chan[ch].ADSRX.SustainIncrease, TRUE);
    SetDlgItemInt(hW, IDC_SADSR7, s_chan[ch].ADSRX.lVolume, TRUE);
    wsprintf(szB, "%08lx", s_chan[ch].ADSRX.EnvelopeVol);
    SetDlgItemText(hW, IDC_SADSR8, szB);

    if (dx)  // something to draw?
    {
        HPEN hPO = (HPEN)SelectObject(hdc, hPAdsr[1]);  // sel A pen
        dn = r.left;
        MoveToEx(hdc, dn, r.bottom, NULL);  // move to bottom left corner

        dn += (ia * r.right) / dx;  // calc A x line pos
        LineTo(hdc, dn, r.top);     // line to AxPos,top

        SelectObject(hdc, hPAdsr[2]);                          // sel D pen
        dn += (id * r.right) / dx;                             // calc D x line pos
        dy = r.top + ((1024 - s_chan[ch].ADSR.SustainLevel) *  // calc the D y pos
                      r.bottom) /
                         1024;  // (our S level is ranged from 0 to 1024)
        LineTo(hdc, dn, dy);    // line to DxPos,SLevel

        SelectObject(hdc, hPAdsr[3]);  // sel S pen
        if (s_chan[ch].ADSR.SustainTime > 10000)
            dm = 1;  // we have to fake the S values... S will
        else         // inc/decrease until channel stop...
            if (s_chan[ch].ADSR.SustainTime == 0)
            dm = 0;  // we dunno here when this will happen,
        else
            dm = 21 - (((s_chan[ch].ADSR.SustainTime / 500)));  // so we do some more ore less angled line,
        dy = dy - (s_chan[ch].ADSR.SustainModeDec * dm);        // roughly depending on the S Time
        if (dy > r.bottom) dy = r.bottom;
        if (dy < r.top) dy = r.top;
        dn += (is * r.right) / dx;
        LineTo(hdc, dn, dy);  // line to SxPos, fake end volume level

        SelectObject(hdc, hPAdsr[4]);  // sel R pen
        dn += (ir * r.right) / dx;     // calc R x line pos
        LineTo(hdc, dn, r.bottom);     // line to RxPos, bottom right y

        SelectObject(hdc, hPO);  // repair pen
    }

    SelectObject(hdc, hBO);  // repair brush
    ReleaseDC(hWS, hdc);     // release context
}

////////////////////////////////////////////////////////////////////////

void DisplayChannelInfos(HWND hW) {
    int ch = iSelChannel;
    char szB[16];

    // channel infos
    SetDlgItemInt(hW, IDC_CI1, s_chan[ch].bOn, TRUE);
    SetDlgItemInt(hW, IDC_CI2, s_chan[ch].bStop, TRUE);
    SetDlgItemInt(hW, IDC_CI3, s_chan[ch].bNoise, TRUE);
    SetDlgItemInt(hW, IDC_CI4, s_chan[ch].bFMod, TRUE);
    SetDlgItemInt(hW, IDC_CI5, s_chan[ch].bReverb, TRUE);
    SetDlgItemInt(hW, IDC_CI6, s_chan[ch].bRVBActive, TRUE);
    SetDlgItemInt(hW, IDC_CI7, s_chan[ch].iRVBNum, TRUE);
    SetDlgItemInt(hW, IDC_CI8, s_chan[ch].iRVBOffset, TRUE);
    SetDlgItemInt(hW, IDC_CI9, s_chan[ch].iRVBRepeat, TRUE);
    SetDlgItemInt(hW, IDC_CI10, (unsigned long)s_chan[ch].pStart - (unsigned long)spuMemC, FALSE);
    SetDlgItemInt(hW, IDC_CI11, (unsigned long)s_chan[ch].pCurr - (unsigned long)spuMemC, FALSE);
    SetDlgItemInt(hW, IDC_CI12, (unsigned long)s_chan[ch].pLoop - (unsigned long)spuMemC, FALSE);
    SetDlgItemInt(hW, IDC_CI13, s_chan[ch].iRightVolume, TRUE);
    SetDlgItemInt(hW, IDC_CI14, s_chan[ch].iLeftVolume, TRUE);
    SetDlgItemInt(hW, IDC_CI15, s_chan[ch].iActFreq, TRUE);
    SetDlgItemInt(hW, IDC_CI16, s_chan[ch].iUsedFreq, TRUE);

    wsprintf(szB, "%04x", s_chan[ch].iRightVolRaw);
    SetDlgItemText(hW, IDC_CI17, szB);
    wsprintf(szB, "%04x", s_chan[ch].iLeftVolRaw);
    SetDlgItemText(hW, IDC_CI18, szB);

    // generic infos
    if (pSpuIrq == 0)
        SetDlgItemInt(hW, IDC_STA1, -1, TRUE);
    else
        SetDlgItemInt(hW, IDC_STA1, (unsigned long)pSpuIrq - (unsigned long)spuMemC, FALSE);
    wsprintf(szB, "%04x", spuCtrl);
    SetDlgItemText(hW, IDC_STA2, szB);
    wsprintf(szB, "%04x", spuStat);
    SetDlgItemText(hW, IDC_STA3, szB);
    SetDlgItemInt(hW, IDC_STA4, spuAddr, TRUE);

    // xa infos
    if (XAPlay <= XAFeed)
        ch = XAFeed - XAPlay;
    else
        ch = (XAFeed - XAStart) + (XAEnd - XAPlay);
    SetDlgItemInt(hW, IDC_XA4, ch, FALSE);
    SetDlgItemInt(hW, IDC_XA5, iLeftXAVol, TRUE);
    SetDlgItemInt(hW, IDC_XA6, iRightXAVol, TRUE);
    if (!xapGlobal) return;
    SetDlgItemInt(hW, IDC_XA1, xapGlobal->freq, TRUE);
    SetDlgItemInt(hW, IDC_XA2, xapGlobal->stereo, TRUE);
    SetDlgItemInt(hW, IDC_XA3, xapGlobal->nsamples, TRUE);
}

////////////////////////////////////////////////////////////////////////
// display everything (called in dialog timer for value refreshing)

void DisplayDebugInfos(HWND hW) {
    DisplayStreamInfos(hW);
    DisplayADSRInfos(hW);
    DisplayChannelInfos(hW);
}

////////////////////////////////////////////////////////////////////////
// main debug dlg handler

BOOL DebugDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        //--------------------------------------------------// init
        case WM_INITDIALOG: {
            int i;
            ShowCursor(TRUE);  // mmm... who is hiding it? main emu? tsts
            iSelChannel = 0;   // sel first channel
            CheckRadioButton(hW, IDC_CHAN1, IDC_CHAN24, IDC_CHAN1);
            if (iUseXA) CheckDlgButton(hW, IDC_XA, TRUE);
            // create brushes/pens
            hBStream[0] = CreateSolidBrush(GetSysColor(COLOR_3DFACE));
            hPAdsr[0] = CreatePen(PS_SOLID, 0, GetSysColor(COLOR_3DFACE));
            for (i = 1; i < 6; i++) {
                hBStream[i] = CreateSolidBrush(crStreamCol[i]);
                hPAdsr[i] = CreatePen(PS_SOLID, 0, crAdsrCol[i]);
            }
            SetTimer(hW, 999, 50, NULL);  // now create update timer
            return TRUE;
        }
        //--------------------------------------------------// destroy
        case WM_DESTROY: {
            int i;
            KillTimer(hW, 999);      // first kill timer
            for (i = 0; i < 6; i++)  // then kill brushes/pens
            {
                DeleteObject(hBStream[i]);
                DeleteObject(hPAdsr[i]);
            }
        } break;
        //--------------------------------------------------// timer
        case WM_TIMER: {
            if (wParam == 999) DisplayDebugInfos(hW);  // update all values
        } break;
        //--------------------------------------------------// command
        case WM_COMMAND: {
            if (wParam == IDCANCEL) iSPUDebugMode = 2;  // cancel? raise flag for destroying the dialog

            if (wParam == IDC_XA) {
                if (IsDlgButtonChecked(hW, wParam))  // -> mute/unmute it
                    iUseXA = 1;
                else
                    iUseXA = 0;
            }

            if (wParam >= IDC_MUTE1 && wParam <= IDC_MUTE24)  // mute clicked?
            {
                if (IsDlgButtonChecked(hW, wParam))  // -> mute/unmute it
                    s_chan[wParam - IDC_MUTE1].iMute = 1;
                else
                    s_chan[wParam - IDC_MUTE1].iMute = 0;
            }
            // all mute/unmute
            if (wParam == IDC_MUTEOFF) SendMessage(hW, WM_MUTE, 0, 0);
            if (wParam == IDC_MUTEON) SendMessage(hW, WM_MUTE, 1, 0);

            if (wParam >= IDC_CHAN1 && wParam <= IDC_CHAN24)  // sel channel
            {
                if (IsDlgButtonChecked(hW, wParam)) {
                    iSelChannel = wParam - IDC_CHAN1;
                    SetDlgItemInt(hW, IDC_CHANNUM, iSelChannel + 1, FALSE);
                }
            }
        } break;
        //--------------------------------------------------// mute
        case WM_MUTE: {  // will be called by the mute/unmute all button and on savestate load
            int i;
            for (i = IDC_MUTE1; i <= IDC_MUTE24; i++) {
                CheckDlgButton(hW, i, wParam);
                if (wParam)
                    s_chan[i - IDC_MUTE1].iMute = 1;
                else
                    s_chan[i - IDC_MUTE1].iMute = 0;
            }
        } break;
        //--------------------------------------------------// size
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) SetFocus(hWMain);  // if we get minimized, set the foxus to the main window
            break;
        //--------------------------------------------------// setcursor
        case WM_SETCURSOR: {
            SetCursor(LoadCursor(NULL, IDC_ARROW));  // force the arrow
            return TRUE;
        }
            //--------------------------------------------------//
    }
    return FALSE;
}

////////////////////////////////////////////////////////////////////////

#endif
