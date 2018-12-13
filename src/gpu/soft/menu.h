/***************************************************************************
                          menu.h  -  description
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

#ifndef _GPU_MENU_H_
#define _GPU_MENU_H_

void DisplayText(void);
void CloseMenu(void);
void InitMenu(void);
void BuildDispMenu(int iInc);
void SwitchDispMenu(int iStep);

#endif // _GPU_MENU_H_
