/***************************************************************************
                          key.c  -  description
                             -------------------
    begin                : Sun Oct 28 2001
    copyright            : (C) 2001 by Pete Bernert
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

#define _IN_KEY

#include "key.h"
#include "draw.h"
#include "externals.h"
#include "gpu.h"
#include "menu.h"

//#include "record.h"

////////////////////////////////////////////////////////////////////////
// KeyBoard handler stuff
////////////////////////////////////////////////////////////////////////

WNDPROC wpOrgWndProc = 0;
unsigned long ulKeybits = 0;
char szGPUKeys[11];

////////////////////////////////////////////////////////////////////////
// keyboard handler
////////////////////////////////////////////////////////////////////////

void CALLBACK GPUshowScreenPic(unsigned char* pMem);
void CALLBACK GPUgetScreenPic(unsigned char* pMem);

LRESULT CALLBACK KeyWndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        //--------------------------------------------------//
        case WM_ACTIVATE:  // some scanline window mode fixing stuff
        case WM_MOVE: {
            if (!iUseScanLines) break;
            if (!iWindowMode) break;
            if (bIsFirstFrame) break;
            MoveScanLineArea(hwnd);
        } break;
        //--------------------------------------------------//
        case WM_KEYDOWN:  // keydown
            if (wParam == (WPARAM)szGPUKeys[2]) ulKeybits |= KEY_RESETTEXSTORE;
            break;
        //--------------------------------------------------//
        case WM_SYSKEYUP:  // alt+enter
            if (wParam == VK_RETURN) bChangeWinMode = TRUE;
            break;
        //--------------------------------------------------//
        case WM_KEYUP:  // key up

            if (iDebugMode && wParam == (WPARAM)szGPUKeys[9]) iFVDisplay = !iFVDisplay;

            if (wParam == (WPARAM)szGPUKeys[0]) {
                if (ulKeybits & KEY_SHOWFPS) {
                    DestroyPic();
                    ulKeybits &= ~KEY_SHOWFPS;
                    DoClearScreenBuffer();
                } else {
                    ulKeybits |= KEY_SHOWFPS;
                    szDispBuf[0] = 0;
                    BuildDispMenu(0);
                }
                break;
            }
            if (wParam == (WPARAM)szGPUKeys[1]) {
                ShowGpuPic();
                break;
            }

#if 0
            if (wParam == (WPARAM)szGPUKeys[6]) {
                if (RECORD_RECORDING == TRUE) {
                    RECORD_RECORDING = FALSE;
                    RECORD_Stop();
                } else {
                    RECORD_RECORDING = TRUE;
                    RECORD_Start();
                }
                BuildDispMenu(0);
                break;
            }
#endif

            if (wParam == (WPARAM)szGPUKeys[2]) {
                SwitchDispMenu(-1);
                break;
            }
            if (wParam == (WPARAM)szGPUKeys[3]) {
                SwitchDispMenu(1);
                break;
            }
            if (wParam == (WPARAM)szGPUKeys[4]) {
                BuildDispMenu(-1);
                break;
            }
            if (wParam == (WPARAM)szGPUKeys[5]) {
                BuildDispMenu(1);
                break;
            }
            if (wParam == (WPARAM)szGPUKeys[7]) {
                bVsync_Key = bVsync_Key == TRUE ? FALSE : TRUE;
                BuildDispMenu(0);
                break;
            }
            if (wParam == (WPARAM)szGPUKeys[8]) {
                iFastFwd = 1 - iFastFwd;
                bSkipNextFrame = FALSE;
                UseFrameSkip = iFastFwd;
                BuildDispMenu(0);
                break;
            }
            break;
            //--------------------------------------------------//
    }
    return wpOrgWndProc(hwnd, message, wParam, lParam);
}

////////////////////////////////////////////////////////////////////////

void SetKeyHandler(void) {
//    if (!wpOrgWndProc)  // setup keyhandler
//    {
//        wpOrgWndProc = (WNDPROC)GetWindowLong(hWGPU, GWL_WNDPROC);
//        SetWindowLong(hWGPU, GWL_WNDPROC, (long)KeyWndProc);
//    }
}

////////////////////////////////////////////////////////////////////////

void ReleaseKeyHandler(void) {
//    if (wpOrgWndProc)
//        SetWindowLong(hWGPU, GWL_WNDPROC,  // set old proc
//                      (long)wpOrgWndProc);
//    wpOrgWndProc = 0;
}
