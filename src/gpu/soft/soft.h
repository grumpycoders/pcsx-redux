/***************************************************************************
                         soft.h  -  description
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
// 2002/06/04 - Lewpy
// - new line drawing funcs
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#ifndef _GPU_SOFT_H_
#define _GPU_SOFT_H_

void offsetPSXLine(void);
void offsetPSX2(void);
void offsetPSX3(void);
void offsetPSX4(void);

void FillSoftwareAreaTrans(short x0, short y0, short x1, short y1, unsigned short col);
void FillSoftwareArea(short x0, short y0, short x1, short y1, unsigned short col);
void drawPoly3G(long rgb1, long rgb2, long rgb3);
void drawPoly4G(long rgb1, long rgb2, long rgb3, long rgb4);
void drawPoly3F(long rgb);
void drawPoly4F(long rgb);
void drawPoly4FT(unsigned char* baseAddr);
void drawPoly4GT(unsigned char* baseAddr);
void drawPoly3FT(unsigned char* baseAddr);
void drawPoly3GT(unsigned char* baseAddr);
void DrawSoftwareSprite(unsigned char* baseAddr, short w, short h, long tx, long ty);
void DrawSoftwareSpriteTWin(unsigned char* baseAddr, long w, long h);
void DrawSoftwareSpriteMirror(unsigned char* baseAddr, long w, long h);
void DrawSoftwareLineShade(long rgb0, long rgb1);
void DrawSoftwareLineFlat(long rgb);

#endif  // _GPU_SOFT_H_
