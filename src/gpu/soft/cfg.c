/***************************************************************************
                          cfg.c  -  description
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

#define _IN_CFG

#include "cfg.h"
#include "externals.h"
#include "gpu.h"
// #include "record.h"

/////////////////////////////////////////////////////////////////////////////
// globals

char szKeyDefaults[11] = {VK_DELETE,   VK_INSERT,   VK_HOME, VK_END, VK_PRIOR, VK_NEXT,
                          VK_MULTIPLY, VK_SUBTRACT, VK_ADD,  VK_F12, 0x00};
char szDevName[128];

////////////////////////////////////////////////////////////////////////
// prototypes

BOOL OnInitCfgDialog(HWND hW);
void OnCfgOK(HWND hW);
BOOL OnInitSoftDialog(HWND hW);
void OnSoftOK(HWND hW);
void OnCfgCancel(HWND hW);
void OnCfgDef1(HWND hW);
void OnCfgDef2(HWND hW);
void OnBugFixes(HWND hW);

void OnRecording(HWND hW);

void SelectDev(HWND hW);
BOOL bTestModes(void);
void OnKeyConfig(HWND hW);
void GetSettings(HWND hW);
void OnClipboard(HWND hW);
void DoDevEnum(HWND hW);
char *pGetConfigInfos(int iCfg);

////////////////////////////////////////////////////////////////////////
// funcs

BOOL CALLBACK SoftDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG:
            return OnInitSoftDialog(hW);

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_DISPMODE1: {
                    CheckDlgButton(hW, IDC_DISPMODE2, FALSE);
                    return TRUE;
                }
                case IDC_DISPMODE2: {
                    CheckDlgButton(hW, IDC_DISPMODE1, FALSE);
                    return TRUE;
                }
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
                case IDC_SELDEV:
                    SelectDev(hW);
                    return TRUE;
                case IDCANCEL:
                    OnCfgCancel(hW);
                    return TRUE;
                case IDOK:
                    OnSoftOK(hW);
                    return TRUE;
                case IDC_CLIPBOARD:
                    OnClipboard(hW);
                    return TRUE;

                case IDC_RECORDING:
                    OnRecording(hW);
                    return TRUE;
            }
        }
    }
#endif
    return FALSE;
}

////////////////////////////////////////////////////////////////////////
// init dlg
////////////////////////////////////////////////////////////////////////

void ComboBoxAddRes(HWND hWC, char *cs) {
    int i = ComboBox_FindString(hWC, -1, cs);
    if (i != CB_ERR) return;
    ComboBox_AddString(hWC, cs);
}

BOOL OnInitSoftDialog(HWND hW) {
    HWND hWC;
    char cs[256];
    int i;
    DEVMODE dv;

    ReadConfig();  // read registry stuff
#if 0
    if (szDevName[0]) SetDlgItemText(hW, IDC_DEVICETXT, szDevName);

    hWC = GetDlgItem(hW, IDC_RESOLUTION);

    memset(&dv, 0, sizeof(DEVMODE));
    dv.dmSize = sizeof(DEVMODE);
    i = 0;

    while (EnumDisplaySettings(NULL, i, &dv)) {
        wsprintf(cs, "%4d x %4d - default", dv.dmPelsWidth, dv.dmPelsHeight);
        ComboBoxAddRes(hWC, cs);
        if (dv.dmDisplayFrequency > 40 && dv.dmDisplayFrequency < 200) {
            wsprintf(cs, "%4d x %4d , %4d Hz", dv.dmPelsWidth, dv.dmPelsHeight, dv.dmDisplayFrequency);
            ComboBoxAddRes(hWC, cs);
        }
        i++;
    }

    ComboBoxAddRes(hWC, " 320 x  200 - default");
    ComboBoxAddRes(hWC, " 320 x  240 - default");
    ComboBoxAddRes(hWC, " 400 x  300 - default");
    ComboBoxAddRes(hWC, " 512 x  384 - default");
    ComboBoxAddRes(hWC, " 640 x  480 - default");
    ComboBoxAddRes(hWC, " 800 x  600 - default");
    ComboBoxAddRes(hWC, "1024 x  768 - default");
    ComboBoxAddRes(hWC, "1152 x  864 - default");
    ComboBoxAddRes(hWC, "1280 x 1024 - default");
    ComboBoxAddRes(hWC, "1600 x 1200 - default");

    if (iRefreshRate)
        wsprintf(cs, "%4d x %4d , %4d Hz", iResX, iResY, iRefreshRate);
    else
        wsprintf(cs, "%4d x %4d - default", iResX, iResY);

    i = ComboBox_FindString(hWC, -1, cs);
    if (i == CB_ERR) i = 0;
    ComboBox_SetCurSel(hWC, i);

    hWC = GetDlgItem(hW, IDC_COLDEPTH);
    ComboBox_AddString(hWC, "16 Bit");
    ComboBox_AddString(hWC, "32 Bit");
    wsprintf(cs, "%d Bit", iColDepth);  // resolution
    i = ComboBox_FindString(hWC, -1, cs);
    if (i == CB_ERR) i = 0;
    ComboBox_SetCurSel(hWC, i);

    hWC = GetDlgItem(hW, IDC_SCANLINES);
    ComboBox_AddString(hWC, "Scanlines disabled");
    ComboBox_AddString(hWC, "Scanlines enabled (standard)");
    ComboBox_AddString(hWC, "Scanlines enabled (double blitting - nVidia fix)");
    ComboBox_SetCurSel(hWC, iUseScanLines);

    SetDlgItemInt(hW, IDC_WINX, LOWORD(iWinSize), FALSE);  // window size
    SetDlgItemInt(hW, IDC_WINY, HIWORD(iWinSize), FALSE);

    if (UseFrameLimit) CheckDlgButton(hW, IDC_USELIMIT, TRUE);
    if (UseFrameSkip) CheckDlgButton(hW, IDC_USESKIPPING, TRUE);
    if (iWindowMode)
        CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE2);
    else
        CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE1);
    if (iSysMemory) CheckDlgButton(hW, IDC_SYSMEMORY, TRUE);
    if (iStopSaver) CheckDlgButton(hW, IDC_STOPSAVER, TRUE);
    if (iUseFixes) CheckDlgButton(hW, IDC_GAMEFIX, TRUE);
    if (iShowFPS) CheckDlgButton(hW, IDC_SHOWFPS, TRUE);
    if (bVsync) CheckDlgButton(hW, IDC_VSYNC, TRUE);
    if (bTransparent) CheckDlgButton(hW, IDC_TRANSPARENT, TRUE);
    if (iDebugMode) CheckDlgButton(hW, IDC_DEBUGMODE, TRUE);

    hWC = GetDlgItem(hW, IDC_NOSTRETCH);  // streching
    ComboBox_AddString(hWC, "Stretch to full window size");
    ComboBox_AddString(hWC, "1:1 (faster with some cards)");
    ComboBox_AddString(hWC, "Scale to window size, keep aspect ratio");
    ComboBox_AddString(hWC, "2xSaI stretching (needs a fast cpu)");
    ComboBox_AddString(hWC, "2xSaI unstretched (needs a fast cpu)");
    ComboBox_AddString(hWC, "Super2xSaI stretching (needs a very fast cpu)");
    ComboBox_AddString(hWC, "Super2xSaI unstretched (needs a very fast cpu)");
    ComboBox_AddString(hWC, "SuperEagle stretching (needs a fast cpu)");
    ComboBox_AddString(hWC, "SuperEagle unstretched (needs a fast cpu)");
    ComboBox_AddString(hWC, "Scale2x stretching (needs a fast cpu)");
    ComboBox_AddString(hWC, "Scale2x unstretched (needs a fast cpu)");
    ComboBox_AddString(hWC, "HQ2X unstretched (needs a fast cpu)");
    ComboBox_AddString(hWC, "HQ2X streched (needs a fast cpu)");
    ComboBox_AddString(hWC, "Scale3x stretching (needs a fast cpu)");
    ComboBox_AddString(hWC, "Scale3x unstretched (needs a fast cpu)");
    ComboBox_AddString(hWC, "HQ3X unstretched (needs a fast cpu)");
    ComboBox_SetCurSel(hWC, iUseNoStretchBlt);

    hWC = GetDlgItem(hW, IDC_DITHER);  // dithering
    ComboBox_AddString(hWC, "No dithering (fastest)");
    ComboBox_AddString(hWC, "Game dependend dithering (slow)");
    ComboBox_AddString(hWC, "Always dither g-shaded polygons (slowest)");
    ComboBox_SetCurSel(hWC, iUseDither);

    if (iFrameLimit == 2)  // frame limit wrapper
        CheckDlgButton(hW, IDC_FRAMEAUTO, TRUE);
    else
        CheckDlgButton(hW, IDC_FRAMEMANUELL, TRUE);

    sprintf(cs, "%.1f", fFrameRate);
    SetDlgItemText(hW, IDC_FRAMELIM, cs);  // set frame rate

#endif
    return TRUE;
}

////////////////////////////////////////////////////////////////////////
// on ok: take vals
////////////////////////////////////////////////////////////////////////

void GetSettings(HWND hW) {
    HWND hWC;
    char cs[256];
    int i, j;
    char *p;

#if 0
    hWC = GetDlgItem(hW, IDC_RESOLUTION);  // get resolution
    i = ComboBox_GetCurSel(hWC);
    ComboBox_GetLBText(hWC, i, cs);
    iResX = atol(cs);
    p = strchr(cs, 'x');
    iResY = atol(p + 1);
    p = strchr(cs, ',');  // added by syo
    if (p)
        iRefreshRate = atol(p + 1);  // get refreshrate
    else
        iRefreshRate = 0;

    hWC = GetDlgItem(hW, IDC_COLDEPTH);  // get color depth
    i = ComboBox_GetCurSel(hWC);
    ComboBox_GetLBText(hWC, i, cs);
    iColDepth = atol(cs);

    hWC = GetDlgItem(hW, IDC_SCANLINES);  // scanlines
    iUseScanLines = ComboBox_GetCurSel(hWC);

    i = GetDlgItemInt(hW, IDC_WINX, NULL, FALSE);  // get win size
    if (i < 50) i = 50;
    if (i > 20000) i = 20000;
    j = GetDlgItemInt(hW, IDC_WINY, NULL, FALSE);
    if (j < 50) j = 50;
    if (j > 20000) j = 20000;
    iWinSize = MAKELONG(i, j);

    if (IsDlgButtonChecked(hW, IDC_DISPMODE2))  // win mode
        iWindowMode = 1;
    else
        iWindowMode = 0;

    if (IsDlgButtonChecked(hW, IDC_USELIMIT))  // fps limit
        UseFrameLimit = 1;
    else
        UseFrameLimit = 0;

    if (IsDlgButtonChecked(hW, IDC_USESKIPPING))  // fps skip
        UseFrameSkip = 1;
    else
        UseFrameSkip = 0;

    if (IsDlgButtonChecked(hW, IDC_GAMEFIX))  // game fix
        iUseFixes = 1;
    else
        iUseFixes = 0;

    if (IsDlgButtonChecked(hW, IDC_SYSMEMORY))  // use system memory
        iSysMemory = 1;
    else
        iSysMemory = 0;

    if (IsDlgButtonChecked(hW, IDC_STOPSAVER))  // stop screen saver
        iStopSaver = 1;
    else
        iStopSaver = 0;

    if (IsDlgButtonChecked(hW, IDC_VSYNC))  // wait VSYNC
        bVsync = bVsync_Key = TRUE;
    else
        bVsync = bVsync_Key = FALSE;

    if (IsDlgButtonChecked(hW, IDC_TRANSPARENT))  // transparent menu
        bTransparent = TRUE;
    else
        bTransparent = FALSE;

    if (IsDlgButtonChecked(hW, IDC_SHOWFPS))  // show fps
        iShowFPS = 1;
    else
        iShowFPS = 0;

    if (IsDlgButtonChecked(hW, IDC_DEBUGMODE))  // debug mode
        iDebugMode = 1;
    else
        iDebugMode = 0;

    hWC = GetDlgItem(hW, IDC_NOSTRETCH);
    iUseNoStretchBlt = ComboBox_GetCurSel(hWC);

    hWC = GetDlgItem(hW, IDC_DITHER);
    iUseDither = ComboBox_GetCurSel(hWC);

    if (IsDlgButtonChecked(hW, IDC_FRAMEAUTO))  // frame rate
        iFrameLimit = 2;
    else
        iFrameLimit = 1;

    GetDlgItemText(hW, IDC_FRAMELIM, cs, 255);
    fFrameRate = (float)atof(cs);
    if (fFrameRate < 10.0f) fFrameRate = 10.0f;
    if (fFrameRate > 200.0f) fFrameRate = 200.0f;
#endif
}

void OnSoftOK(HWND hW) {
    GetSettings(hW);

    if (!iWindowMode && !bTestModes())  // check fullscreen sets
    {
        MessageBox(hW, "Resolution/color depth not supported!", "Error", MB_ICONERROR | MB_OK);
        return;
    }

    WriteConfig();  // write registry

    EndDialog(hW, TRUE);
}

////////////////////////////////////////////////////////////////////////
// on clipboard button
////////////////////////////////////////////////////////////////////////

void OnClipboard(HWND hW) {
#if 0
    HWND hWE = GetDlgItem(hW, IDC_CLPEDIT);
    char *pB;
    GetSettings(hW);
    pB = pGetConfigInfos(1);

    if (pB) {
        SetDlgItemText(hW, IDC_CLPEDIT, pB);
        SendMessage(hWE, EM_SETSEL, 0, -1);
        SendMessage(hWE, WM_COPY, 0, 0);
        free(pB);
        MessageBox(hW,
                   "Configuration info successfully copied to the clipboard\nJust use the PASTE function in another "
                   "program to retrieve the data!",
                   "Copy Info", MB_ICONINFORMATION | MB_OK);
    }
#endif
}

////////////////////////////////////////////////////////////////////////
// Cancel
////////////////////////////////////////////////////////////////////////

void OnCfgCancel(HWND hW) { EndDialog(hW, FALSE); }

////////////////////////////////////////////////////////////////////////
// Bug fixes
////////////////////////////////////////////////////////////////////////

BOOL CALLBACK BugFixesDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG: {
            int i;

            for (i = 0; i < 32; i++) {
                if (dwCfgFixes & (1 << i)) CheckDlgButton(hW, IDC_FIX1 + i, TRUE);
            }
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDCANCEL:
                    EndDialog(hW, FALSE);
                    return TRUE;

                case IDOK: {
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
#endif
    return FALSE;
}

void OnBugFixes(HWND hW) {
    //DialogBox(hInst, MAKEINTRESOURCE(IDD_FIXES), hW, (DLGPROC)BugFixesDlgProc);
}

////////////////////////////////////////////////////////////////////////
// Recording options
////////////////////////////////////////////////////////////////////////

void RefreshCodec(HWND hW) {
#if 0
    char buffer[255];
    union {
        char chFCC[5];
        DWORD dwFCC;
    } fcc;
    ICINFO icinfo;
    memset(&icinfo, 0, sizeof(icinfo));
    icinfo.dwSize = sizeof(icinfo);
    strcpy(fcc.chFCC, "VIDC");
    RECORD_COMPRESSION1.hic = ICOpen(fcc.dwFCC, RECORD_COMPRESSION1.fccHandler, ICMODE_QUERY);
    if (RECORD_COMPRESSION1.hic) {
        ICGetInfo(RECORD_COMPRESSION1.hic, &icinfo, sizeof(icinfo));
        ICClose(RECORD_COMPRESSION1.hic);
        wsprintf(buffer, "16 bit Compression: %ws", icinfo.szDescription);
    } else
        wsprintf(buffer, "16 bit Compression: Full Frames (Uncompressed)");
    SetDlgItemText(hW, IDC_COMPRESSION1, buffer);

    memset(&icinfo, 0, sizeof(icinfo));
    icinfo.dwSize = sizeof(icinfo);
    RECORD_COMPRESSION2.hic = ICOpen(fcc.dwFCC, RECORD_COMPRESSION2.fccHandler, ICMODE_QUERY);
    if (RECORD_COMPRESSION2.hic) {
        ICGetInfo(RECORD_COMPRESSION2.hic, &icinfo, sizeof(icinfo));
        ICClose(RECORD_COMPRESSION2.hic);
        wsprintf(buffer, "24 bit Compression: %ws", icinfo.szDescription);
    } else
        wsprintf(buffer, "24 bit Compression: Full Frames (Uncompressed)");
    SetDlgItemText(hW, IDC_COMPRESSION2, buffer);
#endif
}

BOOL CALLBACK RecordingDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG: {
            HWND hWC;
            CheckDlgButton(hW, IDC_REC_MODE1, RECORD_RECORDING_MODE == 0);
            CheckDlgButton(hW, IDC_REC_MODE2, RECORD_RECORDING_MODE == 1);
            hWC = GetDlgItem(hW, IDC_VIDEO_SIZE);
            ComboBox_ResetContent(hWC);
            ComboBox_AddString(hWC, "Full");
            ComboBox_AddString(hWC, "Half");
            ComboBox_AddString(hWC, "Quarter");
            ComboBox_SetCurSel(hWC, RECORD_VIDEO_SIZE);

            SetDlgItemInt(hW, IDC_REC_WIDTH, RECORD_RECORDING_WIDTH, FALSE);
            SetDlgItemInt(hW, IDC_REC_HEIGHT, RECORD_RECORDING_HEIGHT, FALSE);

            hWC = GetDlgItem(hW, IDC_FRAME_RATE);
            ComboBox_ResetContent(hWC);
            ComboBox_AddString(hWC, "1");
            ComboBox_AddString(hWC, "2");
            ComboBox_AddString(hWC, "3");
            ComboBox_AddString(hWC, "4");
            ComboBox_AddString(hWC, "5");
            ComboBox_AddString(hWC, "6");
            ComboBox_AddString(hWC, "7");
            ComboBox_AddString(hWC, "8");
            ComboBox_SetCurSel(hWC, RECORD_FRAME_RATE_SCALE);
            CheckDlgButton(hW, IDC_COMPRESSION1, RECORD_COMPRESSION_MODE == 0);
            CheckDlgButton(hW, IDC_COMPRESSION2, RECORD_COMPRESSION_MODE == 1);
            RefreshCodec(hW);
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_RECCFG: {
                    if (IsDlgButtonChecked(hW, IDC_COMPRESSION1)) {
                        BITMAPINFOHEADER bitmap = {40, 640, 480, 1, 16, 0, 640 * 480 * 2, 2048, 2048, 0, 0};
                        if (!ICCompressorChoose(hW, ICMF_CHOOSE_DATARATE | ICMF_CHOOSE_KEYFRAME, &bitmap, NULL,
                                                &RECORD_COMPRESSION1, "16 bit Compression"))
                            return TRUE;
                        if (RECORD_COMPRESSION1.cbState > sizeof(RECORD_COMPRESSION_STATE1)) {
                            memset(&RECORD_COMPRESSION1, 0, sizeof(RECORD_COMPRESSION1));
                            memset(&RECORD_COMPRESSION_STATE1, 0, sizeof(RECORD_COMPRESSION_STATE1));
                            RECORD_COMPRESSION1.cbSize = sizeof(RECORD_COMPRESSION1);
                        } else {
                            if (RECORD_COMPRESSION1.lpState != RECORD_COMPRESSION_STATE1)
                                memcpy(RECORD_COMPRESSION_STATE1, RECORD_COMPRESSION1.lpState,
                                       RECORD_COMPRESSION1.cbState);
                        }
                        RECORD_COMPRESSION1.lpState = RECORD_COMPRESSION_STATE1;
                    } else {
                        BITMAPINFOHEADER bitmap = {40, 640, 480, 1, 24, 0, 640 * 480 * 3, 2048, 2048, 0, 0};
                        if (!ICCompressorChoose(hW, ICMF_CHOOSE_DATARATE | ICMF_CHOOSE_KEYFRAME, &bitmap, NULL,
                                                &RECORD_COMPRESSION2, "24 bit Compression"))
                            return TRUE;
                        if (RECORD_COMPRESSION2.cbState > sizeof(RECORD_COMPRESSION_STATE2)) {
                            memset(&RECORD_COMPRESSION2, 0, sizeof(RECORD_COMPRESSION2));
                            memset(&RECORD_COMPRESSION_STATE2, 0, sizeof(RECORD_COMPRESSION_STATE2));
                            RECORD_COMPRESSION2.cbSize = sizeof(RECORD_COMPRESSION2);
                        } else {
                            if (RECORD_COMPRESSION2.lpState != RECORD_COMPRESSION_STATE2)
                                memcpy(RECORD_COMPRESSION_STATE2, RECORD_COMPRESSION2.lpState,
                                       RECORD_COMPRESSION2.cbState);
                        }
                        RECORD_COMPRESSION2.lpState = RECORD_COMPRESSION_STATE2;
                    }
                    RefreshCodec(hW);
                    return TRUE;
                }
                case IDCANCEL:
                    EndDialog(hW, FALSE);
                    return TRUE;

                case IDOK: {
                    HWND hWC;
                    if (IsDlgButtonChecked(hW, IDC_REC_MODE1))
                        RECORD_RECORDING_MODE = 0;
                    else
                        RECORD_RECORDING_MODE = 1;
                    hWC = GetDlgItem(hW, IDC_VIDEO_SIZE);
                    RECORD_VIDEO_SIZE = ComboBox_GetCurSel(hWC);
                    RECORD_RECORDING_WIDTH = GetDlgItemInt(hW, IDC_REC_WIDTH, NULL, FALSE);
                    RECORD_RECORDING_HEIGHT = GetDlgItemInt(hW, IDC_REC_HEIGHT, NULL, FALSE);
                    hWC = GetDlgItem(hW, IDC_FRAME_RATE);
                    RECORD_FRAME_RATE_SCALE = ComboBox_GetCurSel(hWC);
                    if (IsDlgButtonChecked(hW, IDC_COMPRESSION1))
                        RECORD_COMPRESSION_MODE = 0;
                    else
                        RECORD_COMPRESSION_MODE = 1;
                    EndDialog(hW, TRUE);
                    return TRUE;
                }
            }
        }
    }
#endif
    return FALSE;
}

void OnRecording(HWND hW) { 
//    DialogBox(hInst, MAKEINTRESOURCE(IDD_RECORDING), hW, (DLGPROC)RecordingDlgProc);
}

////////////////////////////////////////////////////////////////////////
// default 1: fast
////////////////////////////////////////////////////////////////////////

void OnCfgDef1(HWND hW) {
    HWND hWC;

#if 0
    hWC = GetDlgItem(hW, IDC_RESOLUTION);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_COLDEPTH);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_SCANLINES);
    ComboBox_SetCurSel(hWC, 0);
    CheckDlgButton(hW, IDC_USELIMIT, FALSE);
    CheckDlgButton(hW, IDC_USESKIPPING, TRUE);
    CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE1);
    CheckDlgButton(hW, IDC_FRAMEAUTO, FALSE);
    CheckDlgButton(hW, IDC_FRAMEMANUELL, TRUE);
    CheckDlgButton(hW, IDC_SHOWFPS, FALSE);
    hWC = GetDlgItem(hW, IDC_NOSTRETCH);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_DITHER);
    ComboBox_SetCurSel(hWC, 0);
    SetDlgItemInt(hW, IDC_FRAMELIM, 200, FALSE);
    SetDlgItemInt(hW, IDC_WINX, 320, FALSE);
    SetDlgItemInt(hW, IDC_WINY, 240, FALSE);
    CheckDlgButton(hW, IDC_VSYNC, FALSE);
    CheckDlgButton(hW, IDC_TRANSPARENT, TRUE);
    CheckDlgButton(hW, IDC_DEBUGMODE, FALSE);
#endif
}

////////////////////////////////////////////////////////////////////////
// default 2: nice
////////////////////////////////////////////////////////////////////////

void OnCfgDef2(HWND hW) {
    HWND hWC;

#if 0
    hWC = GetDlgItem(hW, IDC_RESOLUTION);
    ComboBox_SetCurSel(hWC, 2);
    hWC = GetDlgItem(hW, IDC_COLDEPTH);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_SCANLINES);
    ComboBox_SetCurSel(hWC, 0);
    CheckDlgButton(hW, IDC_USELIMIT, TRUE);
    CheckDlgButton(hW, IDC_USESKIPPING, FALSE);
    CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE1);
    CheckDlgButton(hW, IDC_FRAMEAUTO, TRUE);
    CheckDlgButton(hW, IDC_FRAMEMANUELL, FALSE);
    CheckDlgButton(hW, IDC_SHOWFPS, FALSE);
    CheckDlgButton(hW, IDC_VSYNC, FALSE);
    CheckDlgButton(hW, IDC_TRANSPARENT, TRUE);
    CheckDlgButton(hW, IDC_DEBUGMODE, FALSE);
    hWC = GetDlgItem(hW, IDC_NOSTRETCH);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_DITHER);
    ComboBox_SetCurSel(hWC, 2);

    SetDlgItemInt(hW, IDC_FRAMELIM, 200, FALSE);
    SetDlgItemInt(hW, IDC_WINX, 640, FALSE);
    SetDlgItemInt(hW, IDC_WINY, 480, FALSE);
#endif
}

////////////////////////////////////////////////////////////////////////
// read registry
////////////////////////////////////////////////////////////////////////

void ReadConfig(void) {
    HKEY myKey;
    DWORD temp;
    DWORD type;
    DWORD size;

    // predefines
    iResX = 640;
    iResY = 480;
    iColDepth = 16;
    iWindowMode = 0;
    UseFrameLimit = 1;
    UseFrameSkip = 0;
    iFrameLimit = 2;
    fFrameRate = 200.0f;
    iWinSize = MAKELONG(640, 480);
    dwCfgFixes = 0;
    iUseFixes = 0;
    iUseGammaVal = 2048;
    iUseScanLines = 0;
    iUseNoStretchBlt = 0;
    iUseDither = 0;
    iShowFPS = 0;
    iSysMemory = 0;
    iStopSaver = 1;
    bVsync = FALSE;
    bTransparent = FALSE;
    iRefreshRate = 0;
    iDebugMode = 1;
    lstrcpy(szGPUKeys, szKeyDefaults);

    memset(szDevName, 0, 128);
    memset(&guiDev, 0, sizeof(GUID));

#if 0

    // standard Windows psx config (registry)
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\DFXVideo", 0, KEY_ALL_ACCESS,
                     &myKey) == ERROR_SUCCESS) {
        size = 4;
        if (RegQueryValueEx(myKey, "ResX", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResX = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ResY", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResY = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "RefreshRate", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iRefreshRate = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "WinSize", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iWinSize = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "WindowMode", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iWindowMode = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ColDepth", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iColDepth = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseFrameLimit", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            UseFrameLimit = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseFrameSkip", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            UseFrameSkip = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "FrameLimit", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iFrameLimit = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "CfgFixes", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) dwCfgFixes = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseFixes", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iUseFixes = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseScanLines", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iUseScanLines = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ShowFPS", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iShowFPS = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseNoStrechBlt", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iUseNoStretchBlt = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseDither", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iUseDither = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "UseGamma", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iUseGammaVal = (int)temp;
        if (!iFrameLimit) {
            UseFrameLimit = 0;
            UseFrameSkip = 0;
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
        if (RegQueryValueEx(myKey, "UseSysMemory", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iSysMemory = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "StopSaver", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iStopSaver = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "WaitVSYNC", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bVsync = bVsync_Key = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "Transparent", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            bTransparent = (BOOL)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "DebugMode", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
            iDebugMode = (BOOL)temp;
        size = 11;
        RegQueryValueEx(myKey, "GPUKeys", 0, &type, (LPBYTE)&szGPUKeys, &size);
        size = 128;
        RegQueryValueEx(myKey, "DeviceName", 0, &type, (LPBYTE)szDevName, &size);
        size = sizeof(GUID);
        RegQueryValueEx(myKey, "GuiDev", 0, &type, (LPBYTE)&guiDev, &size);

//
// Recording options
//
#define GetDWORD(xa, xb) \
    size = 4;            \
    if (RegQueryValueEx(myKey, xa, 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) xb = (unsigned long)temp;
#define GetBINARY(xa, xb) \
    size = sizeof(xb);    \
    RegQueryValueEx(myKey, xa, 0, &type, (LPBYTE)&xb, &size);

        GetDWORD("RecordingMode", RECORD_RECORDING_MODE);
        GetDWORD("RecordingVideoSize", RECORD_VIDEO_SIZE);
        GetDWORD("RecordingWidth", RECORD_RECORDING_WIDTH);
        GetDWORD("RecordingHeight", RECORD_RECORDING_HEIGHT);
        GetDWORD("RecordingFrameRateScale", RECORD_FRAME_RATE_SCALE);
        GetDWORD("RecordingCompressionMode", RECORD_COMPRESSION_MODE);
        GetBINARY("RecordingCompression1", RECORD_COMPRESSION1);
        GetBINARY("RecordingCompressionState1", RECORD_COMPRESSION_STATE1);
        GetBINARY("RecordingCompression2", RECORD_COMPRESSION2);
        GetBINARY("RecordingCompressionState2", RECORD_COMPRESSION_STATE2);

        if (RECORD_RECORDING_WIDTH > 1024) RECORD_RECORDING_WIDTH = 1024;
        if (RECORD_RECORDING_HEIGHT > 768) RECORD_RECORDING_HEIGHT = 768;
        if (RECORD_VIDEO_SIZE > 2) RECORD_VIDEO_SIZE = 2;
        if (RECORD_FRAME_RATE_SCALE > 7) RECORD_FRAME_RATE_SCALE = 7;
        if (RECORD_COMPRESSION1.cbSize != sizeof(RECORD_COMPRESSION1)) {
            memset(&RECORD_COMPRESSION1, 0, sizeof(RECORD_COMPRESSION1));
            RECORD_COMPRESSION1.cbSize = sizeof(RECORD_COMPRESSION1);
        }
        RECORD_COMPRESSION1.lpState = RECORD_COMPRESSION_STATE1;
        if (RECORD_COMPRESSION2.cbSize != sizeof(RECORD_COMPRESSION2)) {
            memset(&RECORD_COMPRESSION2, 0, sizeof(RECORD_COMPRESSION2));
            RECORD_COMPRESSION2.cbSize = sizeof(RECORD_COMPRESSION2);
        }
        RECORD_COMPRESSION2.lpState = RECORD_COMPRESSION_STATE2;

        //
        // end of recording options
        //

        RegCloseKey(myKey);
    }
#endif

    if (!iColDepth) iColDepth = 32;
    if (iUseFixes) dwActFixes = dwCfgFixes;
    SetFixes();

    if (iUseGammaVal < 0 || iUseGammaVal > 1536) iUseGammaVal = 2048;
}

////////////////////////////////////////////////////////////////////////

void ReadWinSizeConfig(void) {
    HKEY myKey;
    DWORD temp;
    DWORD type;
    DWORD size;

    iResX = 640;
    iResY = 480;
    iWinSize = MAKELONG(320, 240);

    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\DFXVideo", 0, KEY_ALL_ACCESS,
                     &myKey) == ERROR_SUCCESS) {
        size = 4;
        if (RegQueryValueEx(myKey, "ResX", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResX = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "ResY", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iResY = (int)temp;
        size = 4;
        if (RegQueryValueEx(myKey, "WinSize", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) iWinSize = (int)temp;

        RegCloseKey(myKey);
    }
}

////////////////////////////////////////////////////////////////////////
// write registry
////////////////////////////////////////////////////////////////////////

void WriteConfig(void) {
    HKEY myKey;
    DWORD myDisp;
    DWORD temp;

#if 0
    RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\DFXVideo", 0, NULL,
                   REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &myKey, &myDisp);
    temp = iResX;
    RegSetValueEx(myKey, "ResX", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iResY;
    RegSetValueEx(myKey, "ResY", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iRefreshRate;
    RegSetValueEx(myKey, "RefreshRate", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iWinSize;
    RegSetValueEx(myKey, "WinSize", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iWindowMode;
    RegSetValueEx(myKey, "WindowMode", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iColDepth;
    RegSetValueEx(myKey, "ColDepth", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = UseFrameLimit;
    RegSetValueEx(myKey, "UseFrameLimit", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = UseFrameSkip;
    RegSetValueEx(myKey, "UseFrameSkip", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = dwCfgFixes;
    RegSetValueEx(myKey, "CfgFixes", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iUseFixes;
    RegSetValueEx(myKey, "UseFixes", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iUseScanLines;
    RegSetValueEx(myKey, "UseScanLines", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iShowFPS;
    RegSetValueEx(myKey, "ShowFPS", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iUseNoStretchBlt;
    RegSetValueEx(myKey, "UseNoStrechBlt", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iUseDither;
    RegSetValueEx(myKey, "UseDither", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iFrameLimit;
    RegSetValueEx(myKey, "FrameLimit", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iUseGammaVal;
    RegSetValueEx(myKey, "UseGamma", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = (DWORD)fFrameRate;
    RegSetValueEx(myKey, "FrameRate", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = *((DWORD *)&fFrameRate);
    RegSetValueEx(myKey, "FrameRateFloat", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bVsync;
    RegSetValueEx(myKey, "WaitVSYNC", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bTransparent;
    RegSetValueEx(myKey, "Transparent", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iSysMemory;
    RegSetValueEx(myKey, "UseSysMemory", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iStopSaver;
    RegSetValueEx(myKey, "StopSaver", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = iDebugMode;
    RegSetValueEx(myKey, "DebugMode", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    RegSetValueEx(myKey, "GPUKeys", 0, REG_BINARY, (LPBYTE)szGPUKeys, 11);
    RegSetValueEx(myKey, "DeviceName", 0, REG_BINARY, (LPBYTE)szDevName, 128);
    RegSetValueEx(myKey, "GuiDev", 0, REG_BINARY, (LPBYTE)&guiDev, sizeof(GUID));

    //
    // Recording options
    //
    if (RECORD_COMPRESSION1.cbState > sizeof(RECORD_COMPRESSION_STATE1) ||
        RECORD_COMPRESSION1.lpState != RECORD_COMPRESSION_STATE1) {
        memset(&RECORD_COMPRESSION1, 0, sizeof(RECORD_COMPRESSION1));
        memset(&RECORD_COMPRESSION_STATE1, 0, sizeof(RECORD_COMPRESSION_STATE1));
        RECORD_COMPRESSION1.cbSize = sizeof(RECORD_COMPRESSION1);
        RECORD_COMPRESSION1.lpState = RECORD_COMPRESSION_STATE1;
    }
    if (RECORD_COMPRESSION2.cbState > sizeof(RECORD_COMPRESSION_STATE2) ||
        RECORD_COMPRESSION2.lpState != RECORD_COMPRESSION_STATE2) {
        memset(&RECORD_COMPRESSION2, 0, sizeof(RECORD_COMPRESSION2));
        memset(&RECORD_COMPRESSION_STATE2, 0, sizeof(RECORD_COMPRESSION_STATE2));
        RECORD_COMPRESSION2.cbSize = sizeof(RECORD_COMPRESSION2);
        RECORD_COMPRESSION2.lpState = RECORD_COMPRESSION_STATE2;
    }

#define SetDWORD(xa, xb) RegSetValueEx(myKey, xa, 0, REG_DWORD, (LPBYTE)&xb, sizeof(xb));
#define SetBINARY(xa, xb) RegSetValueEx(myKey, xa, 0, REG_BINARY, (LPBYTE)&xb, sizeof(xb));

    SetDWORD("RecordingMode", RECORD_RECORDING_MODE);
    SetDWORD("RecordingVideoSize", RECORD_VIDEO_SIZE);
    SetDWORD("RecordingWidth", RECORD_RECORDING_WIDTH);
    SetDWORD("RecordingHeight", RECORD_RECORDING_HEIGHT);
    SetDWORD("RecordingFrameRateScale", RECORD_FRAME_RATE_SCALE);
    SetDWORD("RecordingCompressionMode", RECORD_COMPRESSION_MODE);
    SetBINARY("RecordingCompression1", RECORD_COMPRESSION1);
    SetBINARY("RecordingCompressionState1", RECORD_COMPRESSION_STATE1);
    SetBINARY("RecordingCompression2", RECORD_COMPRESSION2);
    SetBINARY("RecordingCompressionState2", RECORD_COMPRESSION_STATE2);
    //
    //
    //
    RegCloseKey(myKey);
#endif
}

////////////////////////////////////////////////////////////////////////

HWND gHWND;

static HRESULT WINAPI Enum3DDevicesCallback(GUID *pGUID, LPSTR strDesc, LPSTR strName, LPD3DDEVICEDESC pHALDesc,
                                            LPD3DDEVICEDESC pHELDesc, LPVOID pvContext) {
    BOOL IsHardware;

    // Check params
    if (NULL == pGUID || NULL == pHALDesc || NULL == pHELDesc) return D3DENUMRET_CANCEL;

    // Handle specific device GUIDs. NullDevice renders nothing
    if (IsEqualGUID(pGUID, &IID_IDirect3DNullDevice)) return D3DENUMRET_OK;

    IsHardware = (0 != pHALDesc->dwFlags);
    if (!IsHardware) return D3DENUMRET_OK;

    bDeviceOK = TRUE;

    return D3DENUMRET_OK;
}

static BOOL WINAPI DirectDrawEnumCallbackEx(GUID FAR *pGUID, LPSTR strDesc, LPSTR strName, VOID *pV,
                                            HMONITOR hMonitor) {
    // Use the GUID to create the DirectDraw object, so that information
    // can be extracted from it.

    #if 0
    LPDIRECTDRAW pDD;
    LPDIRECTDRAW4 g_pDD;
    LPDIRECT3D3 pD3D;
    HRESULT(WINAPI * pDDrawCreateFn)(GUID *, LPDIRECTDRAW *, IUnknown *);

    pDDrawCreateFn = (LPVOID)GetProcAddress(hDDrawDLL, "DirectDrawCreate");

    if (pDDrawCreateFn == NULL || FAILED(pDDrawCreateFn(pGUID, &pDD, 0L))) {
        return D3DENUMRET_OK;
    }

    // Query the DirectDraw driver for access to Direct3D.
    if (FAILED(IDirectDraw_QueryInterface(pDD, &IID_IDirectDraw4, (VOID **)&g_pDD))) {
        IDirectDraw_Release(pDD);
        return D3DENUMRET_OK;
    }
    IDirectDraw_Release(pDD);

    // Query the DirectDraw driver for access to Direct3D.

    if (FAILED(IDirectDraw4_QueryInterface(g_pDD, &IID_IDirect3D3, (VOID **)&pD3D))) {
        IDirectDraw4_Release(g_pDD);
        return D3DENUMRET_OK;
    }

    bDeviceOK = FALSE;

    // Now, enumerate all the 3D devices
    IDirect3D3_EnumDevices(pD3D, Enum3DDevicesCallback, NULL);

    #if 0
    if (bDeviceOK) {
        HWND hWC = GetDlgItem(gHWND, IDC_DEVICE);
        int i = ComboBox_AddString(hWC, strDesc);
        GUID *g = (GUID *)malloc(sizeof(GUID));
        if (NULL != pGUID)
            *g = *pGUID;
        else
            memset(g, 0, sizeof(GUID));
        ComboBox_SetItemData(hWC, i, g);
    }
#endif

    IDirect3D3_Release(pD3D);
    IDirectDraw4_Release(g_pDD);
#endif
    return DDENUMRET_OK;
}

//-----------------------------------------------------------------------------

static BOOL WINAPI DirectDrawEnumCallback(GUID FAR *pGUID, LPSTR strDesc, LPSTR strName, VOID *pV) {
    return DirectDrawEnumCallbackEx(pGUID, strDesc, strName, NULL, NULL);
}

//-----------------------------------------------------------------------------

void DoDevEnum(HWND hW) {
#if 0
    LPDIRECTDRAWENUMERATEEX pDDrawEnumFn;

    gHWND = hW;

    pDDrawEnumFn = (LPVOID)GetProcAddress(hDDrawDLL, "DirectDrawEnumerateExA");

    if (pDDrawEnumFn != NULL)
        pDDrawEnumFn(DirectDrawEnumCallbackEx, NULL,
                     DDENUM_ATTACHEDSECONDARYDEVICES | DDENUM_DETACHEDSECONDARYDEVICES | DDENUM_NONDISPLAYDEVICES);
#endif
}

////////////////////////////////////////////////////////////////////////

void FreeGui(HWND hW) {
    int i, iCnt;
#if 0
    HWND hWC = GetDlgItem(hW, IDC_DEVICE);
    iCnt = ComboBox_GetCount(hWC);
    for (i = 0; i < iCnt; i++) {
        free((GUID *)ComboBox_GetItemData(hWC, i));
    }
#endif
}

////////////////////////////////////////////////////////////////////////

BOOL CALLBACK DeviceDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG: {
            HWND hWC;
            int i;
            DoDevEnum(hW);
            hWC = GetDlgItem(hW, IDC_DEVICE);
            i = ComboBox_FindStringExact(hWC, -1, szDevName);
            if (i == CB_ERR) i = 0;
            ComboBox_SetCurSel(hWC, i);
            hWC = GetDlgItem(hW, IDC_GAMMA);
            ScrollBar_SetRange(hWC, 0, 1024, FALSE);
            if (iUseGammaVal == 2048)
                ScrollBar_SetPos(hWC, 512, FALSE);
            else {
                ScrollBar_SetPos(hWC, iUseGammaVal, FALSE);
                CheckDlgButton(hW, IDC_USEGAMMA, TRUE);
            }
        }

        case WM_HSCROLL: {
            HWND hWC = GetDlgItem(hW, IDC_GAMMA);
            int pos = ScrollBar_GetPos(hWC);
            switch (LOWORD(wParam)) {
                case SB_THUMBPOSITION:
                    pos = HIWORD(wParam);
                    break;
                case SB_LEFT:
                    pos = 0;
                    break;
                case SB_RIGHT:
                    pos = 1024;
                    break;
                case SB_LINELEFT:
                    pos -= 16;
                    break;
                case SB_LINERIGHT:
                    pos += 16;
                    break;
                case SB_PAGELEFT:
                    pos -= 128;
                    break;
                case SB_PAGERIGHT:
                    pos += 128;
                    break;
            }
            ScrollBar_SetPos(hWC, pos, TRUE);
            return TRUE;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDCANCEL:
                    FreeGui(hW);
                    EndDialog(hW, FALSE);
                    return TRUE;
                case IDOK: {
                    HWND hWC = GetDlgItem(hW, IDC_DEVICE);
                    int i = ComboBox_GetCurSel(hWC);
                    if (i == CB_ERR) return TRUE;
                    guiDev = *((GUID *)ComboBox_GetItemData(hWC, i));
                    ComboBox_GetLBText(hWC, i, szDevName);
                    FreeGui(hW);

                    if (!IsDlgButtonChecked(hW, IDC_USEGAMMA))
                        iUseGammaVal = 2048;
                    else
                        iUseGammaVal = ScrollBar_GetPos(GetDlgItem(hW, IDC_GAMMA));

                    EndDialog(hW, TRUE);
                    return TRUE;
                }
            }
        }
    }
#endif
    return FALSE;
}

////////////////////////////////////////////////////////////////////////

void SelectDev(HWND hW) {
#if 0
    if (DialogBox(hInst, MAKEINTRESOURCE(IDD_DEVICE), hW, (DLGPROC)DeviceDlgProc) == IDOK) {
        SetDlgItemText(hW, IDC_DEVICETXT, szDevName);
    }
#endif
}

////////////////////////////////////////////////////////////////////////

static HRESULT WINAPI EnumDisplayModesCallback(DDSURFACEDESC2 *pddsd, VOID *pvContext) {
    if (NULL == pddsd) return DDENUMRET_CANCEL;

    if (pddsd->ddpfPixelFormat.dwRGBBitCount == (unsigned int)iColDepth && pddsd->dwWidth == (unsigned int)iResX &&
        pddsd->dwHeight == (unsigned int)iResY) {
        bDeviceOK = TRUE;
        return DDENUMRET_CANCEL;
    }

    return DDENUMRET_OK;
}

////////////////////////////////////////////////////////////////////////

BOOL bTestModes(void) {
#if 0
    LPDIRECTDRAW pDD;
    LPDIRECTDRAW4 g_pDD;
    HRESULT(WINAPI * pDDrawCreateFn)(GUID *, LPDIRECTDRAW *, IUnknown *);

    GUID FAR *guid = 0;
    int i;
    unsigned char *c = (unsigned char *)&guiDev;
    for (i = 0; i < sizeof(GUID); i++, c++) {
        if (*c) {
            guid = &guiDev;
            break;
        }
    }

    bDeviceOK = FALSE;

    pDDrawCreateFn = (LPVOID)GetProcAddress(hDDrawDLL, "DirectDrawCreate");

    if (pDDrawCreateFn == NULL || FAILED(pDDrawCreateFn(guid, &pDD, 0L))) {
        return FALSE;
    }

    if (FAILED(IDirectDraw_QueryInterface(pDD, &IID_IDirectDraw4, (VOID **)&g_pDD))) {
        IDirectDraw_Release(pDD);
        return FALSE;
    }
    IDirectDraw_Release(pDD);

    IDirectDraw4_EnumDisplayModes(g_pDD, 0, NULL, NULL, EnumDisplayModesCallback);

    IDirectDraw4_Release(g_pDD);
#endif
    return bDeviceOK;
}

////////////////////////////////////////////////////////////////////////
// define key dialog
////////////////////////////////////////////////////////////////////////

typedef struct KEYSETSTAG {
    char szName[10];
    char cCode;
} KEYSETS;

KEYSETS tMKeys[] = {{"SPACE", 0x20},   {"PRIOR", 0x21},    {"NEXT", 0x22},     {"END", 0x23},       {"HOME", 0x24},
                    {"LEFT", 0x25},    {"UP", 0x26},       {"RIGHT", 0x27},    {"DOWN", 0x28},      {"SELECT", 0x29},
                    {"PRINT", 0x2A},   {"EXECUTE", 0x2B},  {"SNAPSHOT", 0x2C}, {"INSERT", 0x2D},    {"DELETE", 0x2E},
                    {"HELP", 0x2F},    {"NUMPAD0", 0x60},  {"NUMPAD1", 0x61},  {"NUMPAD2", 0x62},   {"NUMPAD3", 0x63},
                    {"NUMPAD4", 0x64}, {"NUMPAD5", 0x65},  {"NUMPAD6", 0x66},  {"NUMPAD7", 0x67},   {"NUMPAD8", 0x68},
                    {"NUMPAD9", 0x69}, {"MULTIPLY", 0x6A}, {"ADD", 0x6B},      {"SEPARATOR", 0x6C}, {"SUBTRACT", 0x6D},
                    {"DECIMAL", 0x6E}, {"DIVIDE", 0x6F},   {"F9", VK_F9},      {"F10", VK_F10},     {"F11", VK_F11},
                    {"F12", VK_F12},   {"", 0x00}};

void SetGPUKey(HWND hWC, char szKey) {
    int i, iCnt = ComboBox_GetCount(hWC);
    for (i = 0; i < iCnt; i++) {
        if (ComboBox_GetItemData(hWC, i) == szKey) break;
    }
    if (i != iCnt) ComboBox_SetCurSel(hWC, i);
}

BOOL CALLBACK KeyDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
#if 0
    switch (uMsg) {
        case WM_INITDIALOG: {
            int i, j, k;
            char szB[2];
            HWND hWC;
            for (i = IDC_KEY1; i <= IDC_KEY10; i++) {
                hWC = GetDlgItem(hW, i);

                for (j = 0; tMKeys[j].cCode != 0; j++) {
                    k = ComboBox_AddString(hWC, tMKeys[j].szName);
                    ComboBox_SetItemData(hWC, k, tMKeys[j].cCode);
                }
                for (j = 0x30; j <= 0x39; j++) {
                    wsprintf(szB, "%c", j);
                    k = ComboBox_AddString(hWC, szB);
                    ComboBox_SetItemData(hWC, k, j);
                }
                for (j = 0x41; j <= 0x5a; j++) {
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
                case IDC_DEFAULT: {
                    int i;
                    for (i = IDC_KEY1; i <= IDC_KEY10; i++) SetGPUKey(GetDlgItem(hW, i), szKeyDefaults[i - IDC_KEY1]);
                } break;

                case IDCANCEL:
                    EndDialog(hW, FALSE);
                    return TRUE;
                case IDOK: {
                    HWND hWC;
                    int i;
                    for (i = IDC_KEY1; i <= IDC_KEY10; i++) {
                        hWC = GetDlgItem(hW, i);
                        szGPUKeys[i - IDC_KEY1] = (char)ComboBox_GetItemData(hWC, ComboBox_GetCurSel(hWC));
                        if (szGPUKeys[i - IDC_KEY1] < 0x20) szGPUKeys[i - IDC_KEY1] = 0x20;
                    }
                    EndDialog(hW, TRUE);
                    return TRUE;
                }
            }
        }
    }
#endif
    return FALSE;
}

void OnKeyConfig(HWND hW) { 
    //DialogBox(hInst, MAKEINTRESOURCE(IDD_KEYS), hW, (DLGPROC)KeyDlgProc);
}
