/***************************************************************************
                           cfg.c  -  description
                             -------------------
    begin                : Sun Mar 08 2009
    copyright            : (C) 1999-2009 by Pete Bernert
    web                  : www.pbernert.com
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

#define _IN_CFG

/////////////////////////////////////////////////////////////////////////////
// Windows config handling

#include "cfg.h"
#include <stdio.h>
#include "externals.h"
//#include "resource.h"
//#include "stdafx.h"

char szKeyDefaults[7] = {VK_DELETE, VK_INSERT, VK_HOME, VK_END, VK_PRIOR, VK_NEXT, 0x00};

/////////////////////////////////////////////////////////////////////////////
// CCfgDlg dialog

BOOL OnInitCfgDialog(HWND hW);
void OnCfgOK(HWND hW);
void OnCfgCancel(HWND hW);
void OnCfgDef1(HWND hW);
void OnCfgDef2(HWND hW);
void OnBugFixes(HWND hW);
void OnKeyConfig(HWND hW);
void GetSettings(HWND hW);
void OnClipboard(HWND hW);
char *GetConfigInfos(HWND hWE);

BOOL CALLBACK CfgDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG:
            return OnInitCfgDialog(hW);

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_DEF1:
                    OnCfgDef1(hW);
                    return TRUE;
                case IDC_DEF2:
                    OnCfgDef2(hW);
                    return TRUE;
                case IDC_SELFIX:
                    OnBugFixes(hW);
                    return TRUE;
                case IDC_KEYCONFIG:
                    OnKeyConfig(hW);
                    return TRUE;
                case IDCANCEL:
                    OnCfgCancel(hW);
                    return TRUE;
                case IDOK:
                    OnCfgOK(hW);
                    return TRUE;
                case IDC_CLIPBOARD:
                    OnClipboard(hW);
                    return TRUE;
            }
        }
    }
    return FALSE;
#endif
}

/////////////////////////////////////////////////////////////////////////////
// CCfgDlg message handlers

////////////////////////////////////////////////////////////////////////
// init dlg
////////////////////////////////////////////////////////////////////////

void ComboBoxAddRes(HWND hWC, char *cs)  // ADD COMBOBOX RESOURCES
{
    int i = ComboBox_FindString(hWC, -1, cs);
    if (i != CB_ERR) return;
    ComboBox_AddString(hWC, cs);
}

BOOL OnInitCfgDialog(HWND hW)  // INIT CONFIG DIALOG
{
#if 0
    HWND hWC;
    char cs[256];
    int i;
    DEVMODE dv;

    ReadConfig();  // read registry stuff

    //----------------------------------------------------// fill combo with available resolutions

    hWC = GetDlgItem(hW, IDC_RESOLUTION);

    memset(&dv, 0, sizeof(DEVMODE));
    dv.dmSize = sizeof(DEVMODE);
    i = 0;

    while (EnumDisplaySettings(NULL, i, &dv))  // add all resolutions from the driver
    {
        wsprintf(cs, "%4d x %4d", dv.dmPelsWidth, dv.dmPelsHeight);
        ComboBoxAddRes(hWC, cs);
        i++;
    }

    ComboBoxAddRes(hWC, " 640 x  480");  // and also add some common ones
    ComboBoxAddRes(hWC, " 800 x  600");
    ComboBoxAddRes(hWC, "1024 x  768");
    ComboBoxAddRes(hWC, "1152 x  864");
    ComboBoxAddRes(hWC, "1280 x 1024");
    ComboBoxAddRes(hWC, "1600 x 1200");

    wsprintf(cs, "%4d x %4d", iResX, iResY);  // search curr resolution in combo
    i = ComboBox_FindString(hWC, -1, cs);
    if (i == CB_ERR) i = 0;
    ComboBox_SetCurSel(hWC, i);  // and select this one

    //----------------------------------------------------// window size

    SetDlgItemInt(hW, IDC_WINX, LOWORD(iWinSize), FALSE);
    SetDlgItemInt(hW, IDC_WINY, HIWORD(iWinSize), FALSE);

    //----------------------------------------------------// color depth

    hWC = GetDlgItem(hW, IDC_COLORDEPTH);
    ComboBox_AddString(hWC, "16 Bit");
    ComboBox_AddString(hWC, "32 Bit");
    wsprintf(cs, "%d Bit", iColDepth);
    i = ComboBox_FindString(hWC, -1, cs);
    if (i == CB_ERR) i = 0;
    ComboBox_SetCurSel(hWC, i);

    //----------------------------------------------------// vsync

    hWC = GetDlgItem(hW, IDC_VSYNC);
    ComboBox_AddString(hWC, "Driver");
    ComboBox_AddString(hWC, "Off");
    ComboBox_AddString(hWC, "On");
    ComboBox_SetCurSel(hWC, iForceVSync + 1);

    //----------------------------------------------------// vram size

    hWC = GetDlgItem(hW, IDC_VRAMSIZE);
    ComboBox_AddString(hWC, "0 (Autodetect)");
    ComboBox_AddString(hWC, "2");
    ComboBox_AddString(hWC, "4");
    ComboBox_AddString(hWC, "8");
    ComboBox_AddString(hWC, "16");
    ComboBox_AddString(hWC, "32");
    ComboBox_AddString(hWC, "64");
    ComboBox_AddString(hWC, "128 (or more)");

    if (!iVRamSize)
        ComboBox_SetCurSel(hWC, 0);
    else {
        wsprintf(cs, "%d", iVRamSize);
        ComboBox_SetText(hWC, cs);
    }

    //----------------------------------------------------// texture quality

    hWC = GetDlgItem(hW, IDC_TEXQUALITY);
    ComboBox_AddString(hWC, "don't care - Use driver's default textures");
    ComboBox_AddString(hWC, "R4 G4 B4 A4 - Fast, but less colorful");
    ComboBox_AddString(hWC, "R5 G5 B5 A1 - Nice colors, bad transparency");
    ComboBox_AddString(hWC, "R8 G8 B8 A8 - Best colors, more ram needed");
    ComboBox_AddString(hWC, "B8 G8 R8 A8 - Slightly faster with some cards");
    ComboBox_SetCurSel(hWC, iTexQuality);

    //----------------------------------------------------// all kind of on/off options

    if (bDrawDither) CheckDlgButton(hW, IDC_DRAWDITHER, TRUE);
    if (bUseLines) CheckDlgButton(hW, IDC_USELINES, TRUE);
    if (bUseFrameLimit) CheckDlgButton(hW, IDC_USELIMIT, TRUE);
    if (bUseFrameSkip) CheckDlgButton(hW, IDC_USESKIP, TRUE);
    if (bAdvancedBlend) CheckDlgButton(hW, IDC_ADVBLEND, TRUE);
    if (bOpaquePass) CheckDlgButton(hW, IDC_OPAQUE, TRUE);
    // if(bUseAntiAlias)     CheckDlgButton(hW,IDC_USEANTIALIAS,TRUE);
    if (bWindowMode)
        CheckDlgButton(hW, IDC_DISPMODE2, TRUE);
    else
        CheckDlgButton(hW, IDC_DISPMODE1, TRUE);
    if (iUseMask) CheckDlgButton(hW, IDC_USEMASK, TRUE);
    if (bUseFastMdec) CheckDlgButton(hW, IDC_FASTMDEC, TRUE);
    if (bUse15bitMdec) CheckDlgButton(hW, IDC_FASTMDEC2, TRUE);
    if (bUseFixes) CheckDlgButton(hW, IDC_GAMEFIX, TRUE);
    if (bGteAccuracy) CheckDlgButton(hW, IDC_GTEACCURACY, TRUE);
    if (iUseScanLines) CheckDlgButton(hW, IDC_USESCANLINES, TRUE);
    if (iShowFPS) CheckDlgButton(hW, IDC_SHOWFPS, TRUE);
    if (bKeepRatio) CheckDlgButton(hW, IDC_ARATIO, TRUE);
    if (bForceRatio43) CheckDlgButton(hW, IDC_ARATIO43, TRUE);
    if (iBlurBuffer) CheckDlgButton(hW, IDC_BLUR, TRUE);
    if (iNoScreenSaver) CheckDlgButton(hW, IDC_SSAVE, TRUE);

    //----------------------------------------------------// texture filter

    hWC = GetDlgItem(hW, IDC_FILTERTYPE);
    ComboBox_AddString(hWC, "0: None");
    ComboBox_AddString(hWC, "1: Standard - Glitches will happen");
    ComboBox_AddString(hWC, "2: Extended - Removes black borders");
    ComboBox_AddString(hWC, "3: Standard w/o Sprites - unfiltered 2D");
    ComboBox_AddString(hWC, "4: Extended w/o Sprites - unfiltered 2D");
    ComboBox_AddString(hWC, "5: Standard + smoothed Sprites");
    ComboBox_AddString(hWC, "6: Extended + smoothed Sprites");
    ComboBox_SetCurSel(hWC, iFilterType);

    //----------------------------------------------------// hires texture mode

    hWC = GetDlgItem(hW, IDC_HIRESTEX);
    ComboBox_AddString(hWC, "0: None (standard)");
    ComboBox_AddString(hWC, "1: 2xSaI (much vram needed)");
    ComboBox_AddString(hWC, "2: Stretched (filtering needed)");
    ComboBox_SetCurSel(hWC, iHiResTextures);

    //----------------------------------------------------// offscreen drawing

    hWC = GetDlgItem(hW, IDC_OFFSCREEN);
    ComboBox_AddString(hWC, "0: None - Fastest, most glitches");
    ComboBox_AddString(hWC, "1: Minimum - Missing screens");
    ComboBox_AddString(hWC, "2: Standard - OK for most games");
    ComboBox_AddString(hWC, "3: Enhanced - Shows more stuff");
    ComboBox_AddString(hWC, "4: Extended - Can cause garbage");
    ComboBox_SetCurSel(hWC, iOffscreenDrawing);

    //----------------------------------------------------// texture quality

    hWC = GetDlgItem(hW, IDC_FRAMETEX);
    ComboBox_AddString(hWC, "0: Emulated vram - effects need FVP");
    ComboBox_AddString(hWC, "1: Black - Fast but no special effects");
    ComboBox_AddString(hWC, "2: Gfx card buffer - Can be slow");
    ComboBox_AddString(hWC, "3: Gfx card buffer & software - slow");
    ComboBox_SetCurSel(hWC, iFrameTexType);

    //----------------------------------------------------// framebuffer read mode

    hWC = GetDlgItem(hW, IDC_FRAMEREAD);
    ComboBox_AddString(hWC, "0: Emulated vram - OK for most games");
    ComboBox_AddString(hWC, "1: Gfx card buffer reads");
    ComboBox_AddString(hWC, "2: Gfx card buffer moves");
    ComboBox_AddString(hWC, "3: Gfx card buffer reads & moves");
    ComboBox_AddString(hWC, "4: Full software drawing (FVP)");
    ComboBox_SetCurSel(hWC, iFrameReadType);

    //----------------------------------------------------// framerate stuff

    if (iFrameLimit == 2)
        CheckDlgButton(hW, IDC_FRAMEAUTO, TRUE);
    else
        CheckDlgButton(hW, IDC_FRAMEMANUELL, TRUE);

    sprintf(cs, "%.2f", fFrameRate);
    SetDlgItemText(hW, IDC_FRAMELIMIT, cs);
    SetDlgItemInt(hW, IDC_SCANBLEND, iScanBlend, TRUE);

    return TRUE;
#endif
}

////////////////////////////////////////////////////////////////////////
// on ok: take vals
////////////////////////////////////////////////////////////////////////

void GetSettings(HWND hW) {
#if 0
    HWND hWC;
    char cs[256];
    int i, j;
    char *p;

    hWC = GetDlgItem(hW, IDC_VRAMSIZE);  // get vram size
    ComboBox_GetText(hWC, cs, 255);
    iVRamSize = atoi(cs);
    if (iVRamSize < 0) iVRamSize = 0;
    if (iVRamSize > 1024) iVRamSize = 1024;

    hWC = GetDlgItem(hW, IDC_RESOLUTION);  // get resolution
    i = ComboBox_GetCurSel(hWC);
    ComboBox_GetLBText(hWC, i, cs);
    iResX = atol(cs);
    p = strchr(cs, 'x');
    if (p)
        iResY = atol(p + 1);
    else
        iResY = 480;

    hWC = GetDlgItem(hW, IDC_COLORDEPTH);  // get color depth
    i = ComboBox_GetCurSel(hWC);
    ComboBox_GetLBText(hWC, i, cs);
    iColDepth = atol(cs);

    hWC = GetDlgItem(hW, IDC_VSYNC);  // get vsync
    iForceVSync = ComboBox_GetCurSel(hWC) - 1;

    i = GetDlgItemInt(hW, IDC_WINX, NULL, FALSE);  // get win size
    if (i < 100) i = 100;
    if (i > 16384) i = 16384;
    j = GetDlgItemInt(hW, IDC_WINY, NULL, FALSE);
    if (j < 100) j = 100;
    if (j > 16384) j = 16384;
    iWinSize = MAKELONG(i, j);

    hWC = GetDlgItem(hW, IDC_TEXQUALITY);  // texture quality
    iTexQuality = ComboBox_GetCurSel(hWC);

    hWC = GetDlgItem(hW, IDC_FILTERTYPE);  // all kind of options
    iFilterType = ComboBox_GetCurSel(hWC);

    if (IsDlgButtonChecked(hW, IDC_DRAWDITHER))
        bDrawDither = TRUE;
    else
        bDrawDither = FALSE;

    if (IsDlgButtonChecked(hW, IDC_USELINES))
        bUseLines = TRUE;
    else
        bUseLines = FALSE;

    if (IsDlgButtonChecked(hW, IDC_DISPMODE2))
        bWindowMode = TRUE;
    else
        bWindowMode = FALSE;

    if (IsDlgButtonChecked(hW, IDC_ADVBLEND))
        bAdvancedBlend = TRUE;
    else
        bAdvancedBlend = FALSE;

    iOffscreenDrawing = ComboBox_GetCurSel(GetDlgItem(hW, IDC_OFFSCREEN));

    iFrameTexType = ComboBox_GetCurSel(GetDlgItem(hW, IDC_FRAMETEX));
    iFrameReadType = ComboBox_GetCurSel(GetDlgItem(hW, IDC_FRAMEREAD));

    if (IsDlgButtonChecked(hW, IDC_USELIMIT))
        bUseFrameLimit = TRUE;
    else
        bUseFrameLimit = FALSE;

    if (IsDlgButtonChecked(hW, IDC_USESKIP))
        bUseFrameSkip = TRUE;
    else
        bUseFrameSkip = FALSE;

    if (IsDlgButtonChecked(hW, IDC_OPAQUE))
        bOpaquePass = TRUE;
    else
        bOpaquePass = FALSE;

    // if(IsDlgButtonChecked(hW,IDC_USEANTIALIAS))
    //  bUseAntiAlias=TRUE; else bUseAntiAlias=FALSE;

    if (IsDlgButtonChecked(hW, IDC_FASTMDEC))
        bUseFastMdec = TRUE;
    else
        bUseFastMdec = FALSE;

    if (IsDlgButtonChecked(hW, IDC_FASTMDEC2))
        bUse15bitMdec = TRUE;
    else
        bUse15bitMdec = FALSE;

    if (IsDlgButtonChecked(hW, IDC_GAMEFIX))
        bUseFixes = TRUE;
    else
        bUseFixes = FALSE;

    if (IsDlgButtonChecked(hW, IDC_GTEACCURACY))
        bGteAccuracy = TRUE;
    else
        bGteAccuracy = FALSE;

    if (IsDlgButtonChecked(hW, IDC_USESCANLINES))
        iUseScanLines = 1;
    else
        iUseScanLines = 0;

    if (IsDlgButtonChecked(hW, IDC_SHOWFPS))
        iShowFPS = 1;
    else
        iShowFPS = 0;

    if (IsDlgButtonChecked(hW, IDC_ARATIO))
        bKeepRatio = TRUE;
    else
        bKeepRatio = FALSE;

    if (IsDlgButtonChecked(hW, IDC_ARATIO43))
        bForceRatio43 = TRUE;
    else
        bForceRatio43 = FALSE;

    if (IsDlgButtonChecked(hW, IDC_BLUR))
        iBlurBuffer = 1;
    else
        iBlurBuffer = 0;

    if (IsDlgButtonChecked(hW, IDC_SSAVE))
        iNoScreenSaver = 1;
    else
        iNoScreenSaver = 0;

    hWC = GetDlgItem(hW, IDC_HIRESTEX);
    iHiResTextures = ComboBox_GetCurSel(hWC);

    if (IsDlgButtonChecked(hW, IDC_USEMASK)) {
        iUseMask = 1;
        iZBufferDepth = 16;
    } else {
        iUseMask = 0;
        iZBufferDepth = 0;
    }

    iScanBlend = GetDlgItemInt(hW, IDC_SCANBLEND, NULL, TRUE);
    if (iScanBlend > 255) iScanBlend = 0;
    if (iScanBlend < -1) iScanBlend = -1;

    if (IsDlgButtonChecked(hW, IDC_FRAMEAUTO))  // frame rate settings
        iFrameLimit = 2;
    else
        iFrameLimit = 1;

    GetDlgItemText(hW, IDC_FRAMELIMIT, cs, 255);
    fFrameRate = (float)atof(cs);
    if (fFrameRate < 10.0f) fFrameRate = 10.0f;
    if (fFrameRate > 1000.0f) fFrameRate = 1000.0f;
#endif
}

////////////////////////////////////////////////////////////////////////
// OK button
////////////////////////////////////////////////////////////////////////

void OnCfgOK(HWND hW) {
    GetSettings(hW);  // get dialog settings

    WriteConfig();  // write registry

    EndDialog(hW, TRUE);  // close dialog
}

////////////////////////////////////////////////////////////////////////
// Clipboard button
////////////////////////////////////////////////////////////////////////

void OnClipboard(HWND hW) {
#if 0
    HWND hWE = GetDlgItem(hW, IDC_CLPEDIT);
    char *pB;

    GetSettings(hW);           // get dialog setings
    pB = GetConfigInfos(hWE);  // get text infos

    if (pB)  // some text got?
    {
        SetDlgItemText(hW, IDC_CLPEDIT, pB);  // -> set text in invisible edit
        SendMessage(hWE, EM_SETSEL, 0, -1);   // -> sel all in edit
        SendMessage(hWE, WM_COPY, 0, 0);      // -> copy sel to clipboard
        free(pB);                             // -> free helper text buffer

        MessageBox(hW,
                   "Configuration info successfully copied to the clipboard\nJust use the PASTE function in another "
                   "program to retrieve the data!",
                   "Copy Info", MB_ICONINFORMATION | MB_OK);
    }
#endif
}

////////////////////////////////////////////////////////////////////////
// Cancel button (just closes window)
////////////////////////////////////////////////////////////////////////

void OnCfgCancel(HWND hW) { EndDialog(hW, FALSE); }

////////////////////////////////////////////////////////////////////////
// Bug fixes
////////////////////////////////////////////////////////////////////////

BOOL CALLBACK BugFixesDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG:  // init dialog:
        {
            int i;

            for (i = 0; i < 32; i++)  // -> loop all 32 checkboxes
            {
                if (dwCfgFixes & (1 << i))  // --> if fix is active: check box
                    CheckDlgButton(hW, IDC_FIX1 + i, TRUE);
            }
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDCANCEL:
                    EndDialog(hW, FALSE);
                    return TRUE;  // cancel: close window

                case IDOK:  // ok: take settings and close
                {
                    int i;
                    dwCfgFixes = 0;
                    for (i = 0; i < 32; i++) {
                        if (IsDlgButtonChecked(hW, IDC_FIX1 + i)) dwCfgFixes |= (1 << i);
                    }
                    EndDialog(hW, TRUE);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
#endif
}

void OnBugFixes(HWND hW)  // bug fix button:
{
#if 0
    DialogBox(hInst, MAKEINTRESOURCE(IDD_FIXES),  // show fix window
              hW, (DLGPROC)BugFixesDlgProc);
#endif
}

////////////////////////////////////////////////////////////////////////
// default 1: fast
////////////////////////////////////////////////////////////////////////

void OnCfgDef1(HWND hW) {
#if 0
    HWND hWC;

    hWC = GetDlgItem(hW, IDC_RESOLUTION);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_COLORDEPTH);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_VSYNC);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_TEXQUALITY);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_FILTERTYPE);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_OFFSCREEN);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_VRAMSIZE);
    ComboBox_SetCurSel(hWC, 0);

    CheckDlgButton(hW, IDC_TEXLINEAR, FALSE);
    CheckDlgButton(hW, IDC_DRAWDITHER, FALSE);
    CheckDlgButton(hW, IDC_USELINES, FALSE);
    CheckDlgButton(hW, IDC_USELIMIT, FALSE);
    CheckDlgButton(hW, IDC_USESKIP, FALSE);
    CheckDlgButton(hW, IDC_ADVBLEND, FALSE);
    CheckDlgButton(hW, IDC_OPAQUE, TRUE);
    // CheckDlgButton(hW,IDC_USEANTIALIAS,FALSE);
    CheckDlgButton(hW, IDC_DISPMODE2, FALSE);
    CheckDlgButton(hW, IDC_DISPMODE1, TRUE);
    CheckDlgButton(hW, IDC_FRAMEAUTO, TRUE);
    CheckDlgButton(hW, IDC_FRAMEMANUELL, FALSE);
    CheckDlgButton(hW, IDC_SHOWFPS, FALSE);

    ComboBox_SetCurSel(GetDlgItem(hW, IDC_SUBCACHE), 2);
    ComboBox_SetCurSel(GetDlgItem(hW, IDC_FRAMETEX), 1);
    ComboBox_SetCurSel(GetDlgItem(hW, IDC_FRAMEREAD), 0);

    CheckDlgButton(hW, IDC_USEMASK, FALSE);
    CheckDlgButton(hW, IDC_FASTMDEC, TRUE);
    CheckDlgButton(hW, IDC_FASTMDEC2, TRUE);
    CheckDlgButton(hW, IDC_USESCANLINES, FALSE);

    SetDlgItemInt(hW, IDC_FRAMELIMIT, 200, FALSE);
    SetDlgItemInt(hW, IDC_WINX, 640, FALSE);
    SetDlgItemInt(hW, IDC_WINY, 480, FALSE);

    CheckDlgButton(hW, IDC_ARATIO, FALSE);
    CheckDlgButton(hW, IDC_BLUR, FALSE);

    SetDlgItemInt(hW, IDC_SCANBLEND, 0, TRUE);
    ComboBox_SetCurSel(GetDlgItem(hW, IDC_HIRESTEX), 0);
    CheckDlgButton(hW, IDC_SSAVE, FALSE);
#endif
}

////////////////////////////////////////////////////////////////////////
// default 2: nice
////////////////////////////////////////////////////////////////////////

void OnCfgDef2(HWND hW) {
#if 0
    HWND hWC;

    hWC = GetDlgItem(hW, IDC_RESOLUTION);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_COLORDEPTH);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_VSYNC);
    ComboBox_SetCurSel(hWC, 2);
    hWC = GetDlgItem(hW, IDC_TEXQUALITY);
    ComboBox_SetCurSel(hWC, 3);
    hWC = GetDlgItem(hW, IDC_FILTERTYPE);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_OFFSCREEN);
    ComboBox_SetCurSel(hWC, 3);
    hWC = GetDlgItem(hW, IDC_VRAMSIZE);
    ComboBox_SetCurSel(hWC, 0);

    CheckDlgButton(hW, IDC_TEXLINEAR, FALSE);
    CheckDlgButton(hW, IDC_DRAWDITHER, FALSE);
    CheckDlgButton(hW, IDC_USELINES, FALSE);
    CheckDlgButton(hW, IDC_USELIMIT, TRUE);
    CheckDlgButton(hW, IDC_USESKIP, FALSE);
    CheckDlgButton(hW, IDC_ADVBLEND, TRUE);
    CheckDlgButton(hW, IDC_OPAQUE, TRUE);
    // CheckDlgButton(hW,IDC_USEANTIALIAS,FALSE);
    CheckDlgButton(hW, IDC_DISPMODE2, FALSE);
    CheckDlgButton(hW, IDC_DISPMODE1, TRUE);
    CheckDlgButton(hW, IDC_FRAMEAUTO, TRUE);
    CheckDlgButton(hW, IDC_FRAMEMANUELL, FALSE);
    CheckDlgButton(hW, IDC_SHOWFPS, FALSE);

    ComboBox_SetCurSel(GetDlgItem(hW, IDC_SUBCACHE), 2);
    ComboBox_SetCurSel(GetDlgItem(hW, IDC_FRAMETEX), 2);
    ComboBox_SetCurSel(GetDlgItem(hW, IDC_FRAMEREAD), 0);

    CheckDlgButton(hW, IDC_USEMASK, TRUE);
    CheckDlgButton(hW, IDC_FASTMDEC, FALSE);
    CheckDlgButton(hW, IDC_FASTMDEC2, FALSE);
    CheckDlgButton(hW, IDC_USESCANLINES, FALSE);

    SetDlgItemInt(hW, IDC_FRAMELIMIT, 200, FALSE);
    SetDlgItemInt(hW, IDC_WINX, 640, FALSE);
    SetDlgItemInt(hW, IDC_WINY, 480, FALSE);
    CheckDlgButton(hW, IDC_ARATIO, FALSE);
    CheckDlgButton(hW, IDC_BLUR, FALSE);
    SetDlgItemInt(hW, IDC_SCANBLEND, 0, TRUE);
    ComboBox_SetCurSel(GetDlgItem(hW, IDC_HIRESTEX), 0);
    CheckDlgButton(hW, IDC_SSAVE, FALSE);
#endif
}

////////////////////////////////////////////////////////////////////////
// read registry
////////////////////////////////////////////////////////////////////////

void ReadConfig(void)  // read all config vals
{
#if 0
    HKEY myKey;
    DWORD temp;
    DWORD type;
    DWORD size;

    // pre-init all relevant globals

    iResX = 800;
    iResY = 600;
    iColDepth = 32;
    bChangeRes = FALSE;
    bWindowMode = FALSE;
    bFullVRam = FALSE;
    iFilterType = 0;
    bAdvancedBlend = FALSE;
    bDrawDither = FALSE;
    bUseLines = FALSE;
    bUseFrameLimit = TRUE;
    bUseFrameSkip = FALSE;
    iFrameLimit = 2;
    fFrameRate = 200.0f;
    iOffscreenDrawing = 1;
    bOpaquePass = TRUE;
    bUseAntiAlias = FALSE;
    iTexQuality = 0;
    iWinSize = MAKELONG(400, 300);
    iUseMask = 0;
    iZBufferDepth = 0;
    bUseFastMdec = FALSE;
    bUse15bitMdec = FALSE;
    dwCfgFixes = 0;
    bUseFixes = FALSE;
    bGteAccuracy = FALSE;
    iUseScanLines = 0;
    iFrameTexType = 0;
    iFrameReadType = 0;
    iShowFPS = 0;
    bKeepRatio = FALSE;
    bForceRatio43 = FALSE;
    iScanBlend = 0;
    iVRamSize = 0;
    iTexGarbageCollection = 1;
    iBlurBuffer = 0;
    iHiResTextures = 0;
    iNoScreenSaver = 1;
    iForceVSync = -1;

    lstrcpy(szGPUKeys, szKeyDefaults);

    // registry key: still "psemu pro/pete tnt" for compatibility reasons

    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\PeteTNT", 0, KEY_ALL_ACCESS, &myKey) ==
        ERROR_SUCCESS) {
        size = 4;
        if (RegQueryValueEx(myKey, "ResX", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResX = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ResY", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResY = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "WinSize", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iWinSize = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FilterType", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iFilterType = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "DrawDither", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bDrawDither = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseLines", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) bUseLines = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "WindowMode", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bWindowMode = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ColDepth", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iColDepth = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ForceVSync", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iForceVSync = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseFrameLimit", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bUseFrameLimit = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseFrameSkip", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bUseFrameSkip = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FrameLimit", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iFrameLimit = (int)temp;
        if (!iFrameLimit) {
            bUseFrameLimit = TRUE;
            bUseFrameSkip = FALSE;
            iFrameLimit = 2;
        }

        // try to get the float framerate... if none: take int framerate
        fFrameRate = 0.0f;
        size = 4;
        if (RegQueryValueEx(myKey, "FrameRateFloat", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            fFrameRate = *((float *)(&temp));
        if (fFrameRate == 0.0f) {
            fFrameRate = 200.0f;
            size = 4;
            if (RegQueryValueEx(myKey, "FrameRate", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
                fFrameRate = (float)temp;
        }

        size = 4;
        if (RegQueryValueEx(myKey, "UseMultiPass", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bAdvancedBlend = (int)temp;
        size = 4;
        iOffscreenDrawing = -1;
        if (RegQueryValueEx(myKey, "OffscreenDrawingEx", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iOffscreenDrawing = temp;
        if (iOffscreenDrawing == -1 &&
            RegQueryValueEx(myKey, "OffscreenDrawing", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iOffscreenDrawing = temp * 2;
        size = 4;
        if (RegQueryValueEx(myKey, "OpaquePass", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bOpaquePass = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "VRamSize", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iVRamSize = (int)temp;
        //   size = 4;
        //   if(RegQueryValueEx(myKey,"UseAntiAlias",0,&type,(LPBYTE)&temp,&size)==ERROR_SUCCESS)
        //    bUseAntiAlias=(BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "TexQuality", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iTexQuality = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "CfgFixes", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) dwCfgFixes = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseFixes", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) bUseFixes = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "GteAccuracy", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bGteAccuracy = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseMask", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iUseMask = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FastMdec", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bUseFastMdec = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "15BitMdec", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bUse15bitMdec = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseScanLines", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iUseScanLines = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ShowFPS", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iShowFPS = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "KeepRatio", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bKeepRatio = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ForceRatio43", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bForceRatio43 = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ScanBlend", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iScanBlend = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FrameTexType", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iFrameTexType = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FrameReadType", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iFrameReadType = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FullscreenBlur", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iBlurBuffer = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "HiResTextures", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iHiResTextures = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "NoScreenSaver", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iNoScreenSaver = (int)temp;

        size = 7;
        RegQueryValueEx(myKey, "GPUKeys", 0, &type, (LPBYTE)&szGPUKeys, &size);

        RegCloseKey(myKey);
    }
    if (!iColDepth) iColDepth = 32;  // adjust color info
    if (iUseMask)
        iZBufferDepth = 16;  // set zbuffer depth
    else
        iZBufferDepth = 0;
    if (bUseFixes) dwActFixes = dwCfgFixes;     // init game fix global
    if (iFrameReadType == 4) bFullVRam = TRUE;  // set fullvram render flag (soft gpu)
#endif
}

////////////////////////////////////////////////////////////////////////
// read registry: window size (called on fullscreen/window resize)
////////////////////////////////////////////////////////////////////////

void ReadWinSizeConfig(void) {
#if 0
    HKEY myKey;
    DWORD temp;
    DWORD type;
    DWORD size;

    iResX = 800;
    iResY = 600;
    iWinSize = MAKELONG(400, 300);
    iBlurBuffer = 0;

    // registry key: still "psemu pro/pete tnt" for compatibility reasons

    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\PeteTNT", 0, KEY_ALL_ACCESS, &myKey) ==
        ERROR_SUCCESS) {
        size = 4;
        if (RegQueryValueEx(myKey, "ResX", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResX = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ResY", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResY = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "WinSize", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iWinSize = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FullscreenBlur", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iBlurBuffer = (int)temp;
        RegCloseKey(myKey);
    }
#endif
}

////////////////////////////////////////////////////////////////////////
// write registry
////////////////////////////////////////////////////////////////////////

void WriteConfig(void) {
#if 0
    HKEY myKey;
    DWORD myDisp;
    DWORD temp;

    // registry key: still "psemu pro/pete tnt" for compatibility reasons

    RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\PeteTNT", 0, NULL,
                   REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &myKey, &myDisp);
    temp = iResX;
    RegSetValueEx(myKey, "ResX", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iResY;
    RegSetValueEx(myKey, "ResY", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iWinSize;
    RegSetValueEx(myKey, "WinSize", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iFilterType;
    RegSetValueEx(myKey, "FilterType", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bDrawDither;
    RegSetValueEx(myKey, "DrawDither", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bUseLines;
    RegSetValueEx(myKey, "UseLines", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bWindowMode;
    RegSetValueEx(myKey, "WindowMode", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iColDepth;
    RegSetValueEx(myKey, "ColDepth", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iForceVSync;
    RegSetValueEx(myKey, "ForceVSync", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bUseFrameLimit;
    RegSetValueEx(myKey, "UseFrameLimit", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bUseFrameSkip;
    RegSetValueEx(myKey, "UseFrameSkip", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iFrameLimit;
    RegSetValueEx(myKey, "FrameLimit", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = (DWORD)fFrameRate;
    RegSetValueEx(myKey, "FrameRate", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = *((DWORD *)&fFrameRate);
    RegSetValueEx(myKey, "FrameRateFloat", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bAdvancedBlend;
    RegSetValueEx(myKey, "UseMultiPass", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iOffscreenDrawing / 2;
    RegSetValueEx(myKey, "OffscreenDrawing", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iOffscreenDrawing;
    RegSetValueEx(myKey, "OffscreenDrawingEx", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bOpaquePass;
    RegSetValueEx(myKey, "OpaquePass", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iVRamSize;
    RegSetValueEx(myKey, "VRamSize", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    // temp=bUseAntiAlias;
    // RegSetValueEx(myKey,"UseAntiAlias",0,REG_DWORD,(LPBYTE) &temp,sizeof(temp));
    temp = iTexQuality;
    RegSetValueEx(myKey, "TexQuality", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = dwCfgFixes;
    RegSetValueEx(myKey, "CfgFixes", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bUseFixes;
    RegSetValueEx(myKey, "UseFixes", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bGteAccuracy;
    RegSetValueEx(myKey, "GteAccuracy", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iUseMask;
    RegSetValueEx(myKey, "UseMask", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bUseFastMdec;
    RegSetValueEx(myKey, "FastMdec", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bUse15bitMdec;
    RegSetValueEx(myKey, "15BitMdec", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iUseScanLines;
    RegSetValueEx(myKey, "UseScanLines", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iShowFPS;
    RegSetValueEx(myKey, "ShowFPS", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iFrameTexType;
    RegSetValueEx(myKey, "FrameTexType", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iFrameReadType;
    RegSetValueEx(myKey, "FrameReadType", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bKeepRatio;
    RegSetValueEx(myKey, "KeepRatio", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bForceRatio43;
    RegSetValueEx(myKey, "ForceRatio43", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iBlurBuffer;
    RegSetValueEx(myKey, "FullscreenBlur", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iHiResTextures;
    RegSetValueEx(myKey, "HiResTextures", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iNoScreenSaver;
    RegSetValueEx(myKey, "NoScreenSaver", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iScanBlend;
    RegSetValueEx(myKey, "ScanBlend", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    RegSetValueEx(myKey, "GPUKeys", 0, REG_BINARY, (LPBYTE)szGPUKeys, 7);

    RegCloseKey(myKey);
#endif
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
// Key definition window

typedef struct {
    char szName[10];
    char cCode;
} KEYSETS;

// sepcial keys:

KEYSETS tMKeys[] = {{"SPACE", 0x20},   {"PRIOR", 0x21},    {"NEXT", 0x22},     {"END", 0x23},       {"HOME", 0x24},
                    {"LEFT", 0x25},    {"UP", 0x26},       {"RIGHT", 0x27},    {"DOWN", 0x28},      {"SELECT", 0x29},
                    {"PRINT", 0x2A},   {"EXECUTE", 0x2B},  {"SNAPSHOT", 0x2C}, {"INSERT", 0x2D},    {"DELETE", 0x2E},
                    {"HELP", 0x2F},    {"NUMPAD0", 0x60},  {"NUMPAD1", 0x61},  {"NUMPAD2", 0x62},   {"NUMPAD3", 0x63},
                    {"NUMPAD4", 0x64}, {"NUMPAD5", 0x65},  {"NUMPAD6", 0x66},  {"NUMPAD7", 0x67},   {"NUMPAD8", 0x68},
                    {"NUMPAD9", 0x69}, {"MULTIPLY", 0x6A}, {"ADD", 0x6B},      {"SEPARATOR", 0x6C}, {"SUBTRACT", 0x6D},
                    {"DECIMAL", 0x6E}, {"DIVIDE", 0x6F},   {"", 0x00}};

// select key entry in combo box

void SetGPUKey(HWND hWC, char szKey) {
    int i, iCnt = ComboBox_GetCount(hWC);
    for (i = 0; i < iCnt; i++) {
        if (ComboBox_GetItemData(hWC, i) == szKey) break;
    }
    if (i != iCnt) ComboBox_SetCurSel(hWC, i);
}

// key window proc

BOOL CALLBACK KeyDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG:  // init dialog
        {
            int i, j, k;
            char szB[2];
            HWND hWC;
            for (i = IDC_KEY1; i <= IDC_KEY6; i++) {
                hWC = GetDlgItem(hW, i);

                for (j = 0; tMKeys[j].cCode != 0; j++)  // fill special keys in combo
                {
                    k = ComboBox_AddString(hWC, tMKeys[j].szName);
                    ComboBox_SetItemData(hWC, k, tMKeys[j].cCode);
                }
                for (j = 0x30; j <= 0x39; j++)  // fill numbers in combo
                {
                    wsprintf(szB, "%c", j);
                    k = ComboBox_AddString(hWC, szB);
                    ComboBox_SetItemData(hWC, k, j);
                }
                for (j = 0x41; j <= 0x5a; j++)  // fill alphas in combo
                {
                    wsprintf(szB, "%c", j);
                    k = ComboBox_AddString(hWC, szB);
                    ComboBox_SetItemData(hWC, k, j);
                }
                SetGPUKey(GetDlgItem(hW, i), szGPUKeys[i - IDC_KEY1]);
            }
        }
            return TRUE;

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_DEFAULT:  // default button:
                {
                    int i;  // -> set defaults
                    for (i = IDC_KEY1; i <= IDC_KEY6; i++) SetGPUKey(GetDlgItem(hW, i), szKeyDefaults[i - IDC_KEY1]);
                } break;

                case IDCANCEL:  // cancel: just close window
                    EndDialog(hW, FALSE);
                    return TRUE;

                case IDOK:  // ok: take key bindings
                {
                    HWND hWC;
                    int i;
                    for (i = IDC_KEY1; i <= IDC_KEY6; i++) {
                        hWC = GetDlgItem(hW, i);
                        szGPUKeys[i - IDC_KEY1] = ComboBox_GetItemData(hWC, ComboBox_GetCurSel(hWC));
                        if (szGPUKeys[i - IDC_KEY1] < 0x20) szGPUKeys[i - IDC_KEY1] = 0x20;
                    }
                    EndDialog(hW, TRUE);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
#endif
}

void OnKeyConfig(HWND hW)  // call key dialog
{
#if 0
    DialogBox(hInst, MAKEINTRESOURCE(IDD_KEYS), hW, (DLGPROC)KeyDlgProc);
#endif
}

/////////////////////////////////////////////////////////////////////////////
// AboutDlg dialog (Windows)

BOOL CALLBACK AboutDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDOK:
                    EndDialog(hW, TRUE);
                    return TRUE;
            }
        }
    }
    return FALSE;
}
