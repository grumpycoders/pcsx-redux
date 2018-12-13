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

#ifndef _GPU_SOFT_H_
#define _GPU_SOFT_H_

void offsetPSXLine(void);
void offsetPSX2(void);
void offsetPSX3(void);
void offsetPSX4(void);

void FillSoftwareAreaTrans(short x0,short y0,short x1,short y1,unsigned short col);
void FillSoftwareArea(short x0,short y0,short x1,short y1,unsigned short col);
void drawPoly3G(int32_t rgb1, int32_t rgb2, int32_t rgb3);
void drawPoly4G(int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4);
void drawPoly3F(int32_t rgb);
void drawPoly4F(int32_t rgb);
void drawPoly4FT(unsigned char * baseAddr);
void drawPoly4GT(unsigned char * baseAddr);
void drawPoly3FT(unsigned char * baseAddr);
void drawPoly3GT(unsigned char * baseAddr);
void DrawSoftwareSprite(unsigned char * baseAddr,short w,short h,int32_t tx,int32_t ty);
void DrawSoftwareSpriteTWin(unsigned char * baseAddr,int32_t w,int32_t h);
void DrawSoftwareSpriteMirror(unsigned char * baseAddr,int32_t w,int32_t h);
void DrawSoftwareLineShade(int32_t rgb0, int32_t rgb1);
void DrawSoftwareLineFlat(int32_t rgb);

#endif // _GPU_SOFT_H_
