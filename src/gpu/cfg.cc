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

//*************************************************************************//
// History of changes:
//
// 2007/10/27 - Pete
// - added SSSPSX frame limit mode and MxC stretching modes
//
// 2005/04/15 - Pete
// - changed user frame limit to floating point value
//
// 2004/02/08 - Pete
// - added Windows zn config file handling (no need to change it for Linux version)
//
// 2002/11/06 - Pete
// - added 2xSai, Super2xSaI, SuperEagle cfg stuff
//
// 2002/10/04 - Pete
// - added Win debug mode & full vram view key config
//
// 2002/09/27 - linuzappz
// - separated linux gui to conf.c
//
// 2002/06/09 - linuzappz
// - fixed linux about dialog
//
// 2002/02/23 - Pete
// - added capcom fighter special game fix
//
// 2002/01/06 - lu
// - Connected the signal "destroy" to gtk_main_quit() in the ConfDlg, it
//   should fix a possible weird behaviour
//
// 2002/01/06 - lu
// - now fpse for linux has a configurator, some cosmetic changes done.
//
// 2001/12/25 - linuzappz
// - added gtk_main_quit(); in linux config
//
// 2001/12/20 - syo
// - added "Transparent menu" switch
//
// 2001/12/18 - syo
// - added "wait VSYNC" switch
// - support refresh rate change
// - modified key configuration (added toggle wait VSYNC key)
//   (Pete: fixed key buffers and added "- default"
//    refresh rate (=0) for cards not supporting setting the
//    refresh rate)
//
// 2001/12/18 - Darko Matesic
// - added recording configuration
//
// 2001/12/15 - lu
// - now fpsewp has his save and load routines in fpsewp.c
//
// 2001/12/05 - syo
// - added  "use system memory" switch
// - The bug which fails in the change in full-screen mode from window mode is corrected.
// - added  "Stop screen saver" switch
//
// 2001/11/20 - linuzappz
// - added WriteConfig and rewrite ReadConfigFile
// - added SoftDlgProc and AboutDlgProc for Linux (under gtk+-1.2.5)
//
// 2001/11/11 - lu
// - added some ifdef for FPSE layer
//
// 2001/11/09 - Darko Matesic
// - added recording configuration
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#if 0

#include "stdafx.h"

#define _IN_CFG

//-------------------------------------------------------------------------// windows headers

#include <stdio.h>
//#include <vfw.h>
#include "stdafx.h"

#include "gpu/cfg.h"
#include "gpu/externals.h"
#include "gpu/gpu.h"

/////////////////////////////////////////////////////////////////////////////
// CONFIG FILE helpers.... used in (non-fpse) Linux and ZN Windows
/////////////////////////////////////////////////////////////////////////////

char *pConfigFile = NULL;

#ifndef _FPSE

#include <sys/stat.h>

// some helper macros:

#define GetValue(name, var)                     \
    p = strstr(pB, name);                       \
    if (p != NULL) {                            \
        p += strlen(name);                      \
        while ((*p == ' ') || (*p == '=')) p++; \
        if (*p != '\n') var = atoi(p);          \
    }

#define GetFloatValue(name, var)                \
    p = strstr(pB, name);                       \
    if (p != NULL) {                            \
        p += strlen(name);                      \
        while ((*p == ' ') || (*p == '=')) p++; \
        if (*p != '\n') var = (float)atof(p);   \
    }

#define SetValue(name, var)                                                   \
    p = strstr(pB, name);                                                     \
    if (p != NULL) {                                                          \
        p += strlen(name);                                                    \
        while ((*p == ' ') || (*p == '=')) p++;                               \
        if (*p != '\n') {                                                     \
            len = sprintf(t1, "%d", var);                                     \
            strncpy(p, t1, len);                                              \
            if (p[len] != ' ' && p[len] != '\n' && p[len] != 0) p[len] = ' '; \
        }                                                                     \
    } else {                                                                  \
        size += sprintf(pB + size, "%s = %d\n", name, var);                   \
    }

#define SetFloatValue(name, var)                                              \
    p = strstr(pB, name);                                                     \
    if (p != NULL) {                                                          \
        p += strlen(name);                                                    \
        while ((*p == ' ') || (*p == '=')) p++;                               \
        if (*p != '\n') {                                                     \
            len = sprintf(t1, "%.1f", (double)var);                           \
            strncpy(p, t1, len);                                              \
            if (p[len] != ' ' && p[len] != '\n' && p[len] != 0) p[len] = ' '; \
        }                                                                     \
    } else {                                                                  \
        size += sprintf(pB + size, "%s = %.1f\n", name, (double)var);         \
    }

/////////////////////////////////////////////////////////////////////////////

void ReadConfigFile() {
    struct stat buf;
    FILE *in;
    char t[256];
    int len, size;
    char *pB, *p;

    if (pConfigFile)
        strcpy(t, pConfigFile);
    else {
        strcpy(t, "cfg/gpuPeopsSoftX.cfg");
        in = fopen(t, "rb");
        if (!in) {
            strcpy(t, "gpuPeopsSoftX.cfg");
            in = fopen(t, "rb");
            if (!in)
                sprintf(t, "%s/gpuPeopsSoftX.cfg", getenv("HOME"));
            else
                fclose(in);
        } else
            fclose(in);
    }

    if (stat(t, &buf) == -1) return;
    size = buf.st_size;

    in = fopen(t, "rb");
    if (!in) return;

    pB = (char *)malloc(size);
    memset(pB, 0, size);

    len = fread(pB, 1, size, in);
    fclose(in);

    GetValue("SSSPSXLimit", bSSSPSXLimit);

    GetValue("UseFrameLimit", UseFrameLimit);
    if (UseFrameLimit < 0) UseFrameLimit = 0;
    if (UseFrameLimit > 1) UseFrameLimit = 1;

    GetValue("UseFrameSkip", UseFrameSkip);
    if (UseFrameSkip < 0) UseFrameSkip = 0;
    if (UseFrameSkip > 1) UseFrameSkip = 1;

    GetValue("FPSDetection", iFrameLimit);
    if (iFrameLimit < 1) iFrameLimit = 1;
    if (iFrameLimit > 2) iFrameLimit = 2;

    GetFloatValue("FrameRate", fFrameRate);
    if (fFrameRate < 10.0f) fFrameRate = 10.0f;
    if (fFrameRate > 1000.0f) fFrameRate = 1000.0f;

    GetValue("CfgFixes", dwCfgFixes);

    GetValue("UseFixes", iUseFixes);
    if (iUseFixes < 0) iUseFixes = 0;
    if (iUseFixes > 1) iUseFixes = 1;

    free(pB);
}

#endif

/////////////////////////////////////////////////////////////////////////////
// globals

char szKeyDefaults[11] = {VK_DELETE,   VK_INSERT,   VK_HOME, VK_END, VK_PRIOR, VK_NEXT,
                          VK_MULTIPLY, VK_SUBTRACT, VK_ADD,  VK_F12, 0x00};

////////////////////////////////////////////////////////////////////////
// prototypes

bool OnInitSoftDialog(HWND hW);
void OnSoftOK(HWND hW);
void OnCfgCancel(HWND hW);
void OnCfgDef1(HWND hW);
void OnCfgDef2(HWND hW);
void OnBugFixes(HWND hW);

void OnRecording(HWND hW);

void SelectDev(HWND hW);
bool bTestModes(void);
void OnKeyConfig(HWND hW);
void GetSettings(HWND hW);
void OnClipboard(HWND hW);
void DoDevEnum(HWND hW);
char *pGetConfigInfos(int iCfg);

////////////////////////////////////////////////////////////////////////
// funcs

bool SoftDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG:
            return OnInitSoftDialog(hW);

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_DISPMODE1: {
                    CheckDlgButton(hW, IDC_DISPMODE2, false);
                    return true;
                }
                case IDC_DISPMODE2: {
                    CheckDlgButton(hW, IDC_DISPMODE1, false);
                    return true;
                }
                case IDC_DEF1:
                    OnCfgDef1(hW);
                    return true;
                case IDC_DEF2:
                    OnCfgDef2(hW);
                    return true;
                case IDC_SELFIX:
                    OnBugFixes(hW);
                    return true;
                case IDC_KEYCONFIG:
                    OnKeyConfig(hW);
                    return true;
                case IDC_SELDEV:
                    SelectDev(hW);
                    return true;
                case IDCANCEL:
                    OnCfgCancel(hW);
                    return true;
                case IDOK:
                    OnSoftOK(hW);
                    return true;
                case IDC_CLIPBOARD:
                    OnClipboard(hW);
                    return true;

                case IDC_RECORDING:
                    OnRecording(hW);
                    return true;
            }
        }
    }
    return false;
}

////////////////////////////////////////////////////////////////////////
// init dlg
////////////////////////////////////////////////////////////////////////

void ComboBoxAddRes(HWND hWC, const char *cs) {
    int i = ComboBox_FindString(hWC, -1, cs);
    if (i != CB_ERR) return;
    ComboBox_AddString(hWC, cs);
}

bool OnInitSoftDialog(HWND hW) {
    HWND hWC;
    char cs[256];
    int i;
    DEVMODE dv;

    ReadGPUConfig();  // read registry stuff

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

    if (UseFrameLimit) CheckDlgButton(hW, IDC_USELIMIT, true);
    if (UseFrameSkip) CheckDlgButton(hW, IDC_USESKIPPING, true);
    if (iWindowMode)
        CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE2);
    else
        CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE1);
    if (iUseFixes) CheckDlgButton(hW, IDC_GAMEFIX, true);
    if (bTransparent) CheckDlgButton(hW, IDC_TRANSPARENT, true);
    if (bSSSPSXLimit) CheckDlgButton(hW, IDC_SSSPSXLIMIT, true);

    hWC = GetDlgItem(hW, IDC_NOSTRETCH);  // stretching
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
    ComboBox_AddString(hWC, "HQ2X unstretched (Fast CPU+mmx)");
    ComboBox_AddString(hWC, "HQ2X stretched (Fast CPU+mmx)");
    ComboBox_AddString(hWC, "Scale3x stretching (needs a fast cpu)");
    ComboBox_AddString(hWC, "Scale3x unstretched (needs a fast cpu)");
    ComboBox_AddString(hWC, "HQ3X unstretched (Fast CPU+mmx)");
    ComboBox_AddString(hWC, "HQ3X stretching (Fast CPU+mmx)");

    if (iFrameLimit == 2)  // frame limit wrapper
        CheckDlgButton(hW, IDC_FRAMEAUTO, true);
    else
        CheckDlgButton(hW, IDC_FRAMEMANUELL, true);

    sprintf(cs, "%.2f", fFrameRate);
    SetDlgItemText(hW, IDC_FRAMELIM, cs);  // set frame rate

    return true;
}

////////////////////////////////////////////////////////////////////////
// on ok: take vals
////////////////////////////////////////////////////////////////////////

void GetSettings(HWND hW) {
    HWND hWC;
    char cs[256];
    int i, j;
    char *p;

    hWC = GetDlgItem(hW, IDC_RESOLUTION);  // get resolution
    i = ComboBox_GetCurSel(hWC);
    ComboBox_GetLBText(hWC, i, cs);
    p = strchr(cs, 'x');
    p = strchr(cs, ',');  // added by syo

    hWC = GetDlgItem(hW, IDC_COLDEPTH);  // get color depth
    i = ComboBox_GetCurSel(hWC);
    ComboBox_GetLBText(hWC, i, cs);
    iColDepth = atol(cs);

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

    if (IsDlgButtonChecked(hW, IDC_TRANSPARENT))  // transparent menu
        bTransparent = true;
    else
        bTransparent = false;

    if (IsDlgButtonChecked(hW, IDC_SSSPSXLIMIT))  // SSSPSX fps limit mode
        bSSSPSXLimit = true;
    else
        bSSSPSXLimit = false;

    if (IsDlgButtonChecked(hW, IDC_FRAMEAUTO))  // frame rate
        iFrameLimit = 2;
    else
        iFrameLimit = 1;

    GetDlgItemText(hW, IDC_FRAMELIM, cs, 255);
    fFrameRate = (float)atof(cs);

    if (fFrameRate < 10.0f) fFrameRate = 10.0f;
    if (fFrameRate > 1000.0f) fFrameRate = 1000.0f;
}

void OnSoftOK(HWND hW) {
    GetSettings(hW);

    if (!iWindowMode && !bTestModes())  // check fullscreen sets
    {
        MessageBox(hW, "Resolution/color depth not supported!", "Error", MB_ICONERROR | MB_OK);
        return;
    }

    WriteGPUConfig();  // write registry

    EndDialog(hW, true);
}

////////////////////////////////////////////////////////////////////////
// on clipboard button
////////////////////////////////////////////////////////////////////////

void OnClipboard(HWND hW) {
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
}

////////////////////////////////////////////////////////////////////////
// Cancel
////////////////////////////////////////////////////////////////////////

void OnCfgCancel(HWND hW) { EndDialog(hW, false); }

////////////////////////////////////////////////////////////////////////
// Bug fixes
////////////////////////////////////////////////////////////////////////

bool BugFixesDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_INITDIALOG: {
            int i;

            for (i = 0; i < 32; i++) {
                if (dwCfgFixes & (1 << i)) CheckDlgButton(hW, IDC_FIX1 + i, true);
            }
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDCANCEL:
                    EndDialog(hW, false);
                    return true;

                case IDOK: {
                    int i;
                    dwCfgFixes = 0;
                    for (i = 0; i < 32; i++) {
                        if (IsDlgButtonChecked(hW, IDC_FIX1 + i)) dwCfgFixes |= (1 << i);
                    }
                    EndDialog(hW, true);
                    return true;
                }
            }
        }
    }
    return false;
}

void OnBugFixes(HWND hW) { DialogBox(0, MAKEINTRESOURCE(IDD_FIXES), hW, (DLGPROC)BugFixesDlgProc); }

////////////////////////////////////////////////////////////////////////
// Recording options
////////////////////////////////////////////////////////////////////////

void RefreshCodec(HWND hW) {}

bool RecordingDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) { return false; }

void OnRecording(HWND hW) { DialogBox(0, MAKEINTRESOURCE(IDD_RECORDING), hW, (DLGPROC)RecordingDlgProc); }

////////////////////////////////////////////////////////////////////////
// default 1: fast
////////////////////////////////////////////////////////////////////////

void OnCfgDef1(HWND hW) {
    HWND hWC;

    hWC = GetDlgItem(hW, IDC_RESOLUTION);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_COLDEPTH);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_SCANLINES);
    ComboBox_SetCurSel(hWC, 0);
    CheckDlgButton(hW, IDC_USELIMIT, false);
    CheckDlgButton(hW, IDC_USESKIPPING, true);
    CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE1);
    CheckDlgButton(hW, IDC_FRAMEAUTO, false);
    CheckDlgButton(hW, IDC_FRAMEMANUELL, true);
    CheckDlgButton(hW, IDC_SHOWFPS, false);
    hWC = GetDlgItem(hW, IDC_NOSTRETCH);
    ComboBox_SetCurSel(hWC, 1);
    hWC = GetDlgItem(hW, IDC_DITHER);
    ComboBox_SetCurSel(hWC, 0);
    SetDlgItemInt(hW, IDC_FRAMELIM, 200, false);
    SetDlgItemInt(hW, IDC_WINX, 320, false);
    SetDlgItemInt(hW, IDC_WINY, 240, false);
    CheckDlgButton(hW, IDC_VSYNC, false);
    CheckDlgButton(hW, IDC_TRANSPARENT, true);
    CheckDlgButton(hW, IDC_DEBUGMODE, false);
}

////////////////////////////////////////////////////////////////////////
// default 2: nice
////////////////////////////////////////////////////////////////////////

void OnCfgDef2(HWND hW) {
    HWND hWC;

    hWC = GetDlgItem(hW, IDC_RESOLUTION);
    ComboBox_SetCurSel(hWC, 2);
    hWC = GetDlgItem(hW, IDC_COLDEPTH);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_SCANLINES);
    ComboBox_SetCurSel(hWC, 0);
    CheckDlgButton(hW, IDC_USELIMIT, true);
    CheckDlgButton(hW, IDC_USESKIPPING, false);
    CheckRadioButton(hW, IDC_DISPMODE1, IDC_DISPMODE2, IDC_DISPMODE1);
    CheckDlgButton(hW, IDC_FRAMEAUTO, true);
    CheckDlgButton(hW, IDC_FRAMEMANUELL, false);
    CheckDlgButton(hW, IDC_SHOWFPS, false);
    CheckDlgButton(hW, IDC_VSYNC, false);
    CheckDlgButton(hW, IDC_TRANSPARENT, true);
    CheckDlgButton(hW, IDC_DEBUGMODE, false);
    hWC = GetDlgItem(hW, IDC_NOSTRETCH);
    ComboBox_SetCurSel(hWC, 0);
    hWC = GetDlgItem(hW, IDC_DITHER);
    ComboBox_SetCurSel(hWC, 2);

    SetDlgItemInt(hW, IDC_FRAMELIM, 200, false);
    SetDlgItemInt(hW, IDC_WINX, 640, false);
    SetDlgItemInt(hW, IDC_WINY, 480, false);
}

////////////////////////////////////////////////////////////////////////
// read registry
////////////////////////////////////////////////////////////////////////

void ReadGPUConfig(void) {
    HKEY myKey;
    DWORD temp;
    DWORD type;
    DWORD size;

    // predefines
    iColDepth = 16;
    iWindowMode = 0;
    UseFrameLimit = 1;
    UseFrameSkip = 0;
    iFrameLimit = 2;
    fFrameRate = 200.0f;
    dwCfgFixes = 0;
    iUseFixes = 0;
    bTransparent = false;
    bSSSPSXLimit = false;
    lstrcpy(szGPUKeys, szKeyDefaults);

    // zn Windows config file
    if (pConfigFile) ReadConfigFile();
    // standard Windows psx config (registry)
    else {
        if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\PeteSoft", 0, KEY_ALL_ACCESS,
                         &myKey) == ERROR_SUCCESS) {
            size = 4;
            if (RegQueryValueEx(myKey, "WindowMode", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
                iWindowMode = (int)temp;
            size = 4;
            if (RegQueryValueEx(myKey, "ColDepth", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
                iColDepth = (int)temp;
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
            if (RegQueryValueEx(myKey, "CfgFixes", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
                dwCfgFixes = (int)temp;
            size = 4;
            if (RegQueryValueEx(myKey, "UseFixes", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
                iUseFixes = (int)temp;
            size = 4;
            if (!iFrameLimit) {
                UseFrameLimit = 1;
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
            if (RegQueryValueEx(myKey, "Transparent", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
                bTransparent = (bool)temp;
            size = 4;
            if (RegQueryValueEx(myKey, "SSSPSXLimit", 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS)
                bSSSPSXLimit = (bool)temp;
            size = 11;
            RegQueryValueEx(myKey, "GPUKeys", 0, &type, (LPBYTE)&szGPUKeys, &size);

//
// Recording options
//
#define GetDWORD(xa, xb) \
    size = 4;            \
    if (RegQueryValueEx(myKey, xa, 0, &type, (LPBYTE)&temp, &size) == ERROR_SUCCESS) xb = (uint32_t)temp;
#define GetBINARY(xa, xb) \
    size = sizeof(xb);    \
    RegQueryValueEx(myKey, xa, 0, &type, (LPBYTE)&xb, &size);

            //
            // end of recording options
            //

            RegCloseKey(myKey);
        }
    }

    if (!iColDepth) iColDepth = 32;
    if (iUseFixes) dwActFixes = dwCfgFixes;
    SetFixes();
}

////////////////////////////////////////////////////////////////////////

void ReadWinSizeConfig(void) {}

////////////////////////////////////////////////////////////////////////
// write registry
////////////////////////////////////////////////////////////////////////

void WriteGPUConfig(void) {
    HKEY myKey;
    DWORD myDisp;
    DWORD temp;

    RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\Vision Thing\\PSEmu Pro\\GPU\\PeteSoft", 0, NULL,
                   REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &myKey, &myDisp);
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
    temp = iFrameLimit;
    RegSetValueEx(myKey, "FrameLimit", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = (DWORD)fFrameRate;
    RegSetValueEx(myKey, "FrameRate", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = *((DWORD *)&fFrameRate);
    RegSetValueEx(myKey, "FrameRateFloat", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bTransparent;
    RegSetValueEx(myKey, "Transparent", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    temp = bSSSPSXLimit;
    RegSetValueEx(myKey, "SSSPSXLimit", 0, REG_DWORD, (LPBYTE)&temp, sizeof(temp));
    RegSetValueEx(myKey, "GPUKeys", 0, REG_BINARY, (LPBYTE)szGPUKeys, 11);

    //
    //
    //
    RegCloseKey(myKey);
}

////////////////////////////////////////////////////////////////////////

HWND gHWND;

static bool WINAPI DirectDrawEnumCallbackEx(GUID FAR *pGUID, LPSTR strDesc, LPSTR strName, VOID *pV,
                                            HMONITOR hMonitor) {
    // Use the GUID to create the DirectDraw object, so that information
    // can be extracted from it.
}

//-----------------------------------------------------------------------------

static bool WINAPI DirectDrawEnumCallback(GUID FAR *pGUID, LPSTR strDesc, LPSTR strName, VOID *pV) {
    return DirectDrawEnumCallbackEx(pGUID, strDesc, strName, NULL, NULL);
}

//-----------------------------------------------------------------------------

void DoDevEnum(HWND hW) {}

////////////////////////////////////////////////////////////////////////

void FreeGui(HWND hW) {
    int i, iCnt;
    HWND hWC = GetDlgItem(hW, IDC_DEVICE);
    iCnt = ComboBox_GetCount(hWC);
    for (i = 0; i < iCnt; i++) {
        free((GUID *)ComboBox_GetItemData(hWC, i));
    }
}

////////////////////////////////////////////////////////////////////////

bool DeviceDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) { return false; }

////////////////////////////////////////////////////////////////////////

void SelectDev(HWND hW) {}

////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////

bool bTestModes(void) { return false; }

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

bool KeyDlgProc(HWND hW, UINT uMsg, WPARAM wParam, LPARAM lParam) {
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
            return true;

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_DEFAULT: {
                    int i;
                    for (i = IDC_KEY1; i <= IDC_KEY10; i++) SetGPUKey(GetDlgItem(hW, i), szKeyDefaults[i - IDC_KEY1]);
                } break;

                case IDCANCEL:
                    EndDialog(hW, false);
                    return true;
                case IDOK: {
                    HWND hWC;
                    int i;
                    for (i = IDC_KEY1; i <= IDC_KEY10; i++) {
                        hWC = GetDlgItem(hW, i);
                        szGPUKeys[i - IDC_KEY1] = (char)ComboBox_GetItemData(hWC, ComboBox_GetCurSel(hWC));
                        if (szGPUKeys[i - IDC_KEY1] < 0x20) szGPUKeys[i - IDC_KEY1] = 0x20;
                    }
                    EndDialog(hW, true);
                    return true;
                }
            }
        }
    }
    return false;
}

void OnKeyConfig(HWND hW) { DialogBox(0, MAKEINTRESOURCE(IDD_KEYS), hW, (DLGPROC)KeyDlgProc); }

#endif
