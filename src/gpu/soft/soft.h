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

#pragma once

#include "gpu/soft/prim.h"

namespace PCSX {

namespace SoftGPU {

class SoftRenderer : public Prim {
    virtual void offsetPSXLine() final;
    virtual void offsetPSX2() final;
    virtual void offsetPSX3() final;
    virtual void offsetPSX4() final;

    virtual void FillSoftwareAreaTrans(short x0, short y0, short x1, short y1, unsigned short col) final;
    virtual void FillSoftwareArea(short x0, short y0, short x1, short y1, unsigned short col) final;
    virtual void drawPoly3G(long rgb1, long rgb2, long rgb3) final;
    virtual void drawPoly4G(long rgb1, long rgb2, long rgb3, long rgb4) final;
    virtual void drawPoly3F(long rgb) final;
    virtual void drawPoly4F(long rgb) final;
    virtual void drawPoly4FT(unsigned char *baseAddr) final;
    virtual void drawPoly4GT(unsigned char *baseAddr) final;
    virtual void drawPoly3FT(unsigned char *baseAddr) final;
    virtual void drawPoly3GT(unsigned char *baseAddr) final;
    virtual void DrawSoftwareSprite(unsigned char *baseAddr, short w, short h, long tx, long ty) final;
    virtual void DrawSoftwareSpriteTWin(unsigned char *baseAddr, long w, long h) final;
    virtual void DrawSoftwareSpriteMirror(unsigned char *baseAddr, long w, long h) final;
    virtual void DrawSoftwareLineShade(long rgb0, long rgb1) final;
    virtual void DrawSoftwareLineFlat(long rgb) final;
};

}  // namespace SoftGPU

}  // namespace PCSX
