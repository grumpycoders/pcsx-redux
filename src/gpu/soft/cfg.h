/***************************************************************************
                          cfg.h  -  description
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

#ifndef _GPU_CFG_H_
#define _GPU_CFG_H_

#include <windows.h>

void ReadConfig(void);
void WriteConfig(void);
void ReadWinSizeConfig(void);

#ifdef _WIN32
BOOL CALLBACK SoftDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam ); 
#else
void SoftDlgProc(void);
void AboutDlgProc(void);
#endif

#endif
