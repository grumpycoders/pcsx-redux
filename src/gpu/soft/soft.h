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

    short Ymin;
    short Ymax;

    bool IsNoRect();

    bool SetupSections_F(short x1, short y1, short x2, short y2, short x3, short y3);
    bool SetupSections_G(short x1, short y1, short x2, short y2, short x3, short y3, long rgb1, long rgb2, long rgb3);
    bool SetupSections_FT(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                          short ty2, short tx3, short ty3);
    bool SetupSections_GT(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                          short ty2, short tx3, short ty3, long rgb1, long rgb2, long rgb3);
    bool SetupSections_F4(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4);
    bool SetupSections_FT4(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                           short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4);
    bool SetupSections_GT4(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                           short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, long rgb1,
                           long rgb2, long rgb3, long rgb4);

    void GetShadeTransCol_Dither(unsigned short *pdest, long m1, long m2, long m3);
    void GetShadeTransCol(unsigned short *pdest, unsigned short color);
    void GetShadeTransCol32(unsigned long *pdest, unsigned long color);
    void GetTextureTransColG(unsigned short *pdest, unsigned short color);
    void GetTextureTransColG_S(unsigned short *pdest, unsigned short color);
    void GetTextureTransColG_SPR(unsigned short *pdest, unsigned short color);
    void GetTextureTransColG32(unsigned long *pdest, unsigned long color);
    void GetTextureTransColG32_S(unsigned long *pdest, unsigned long color);
    void GetTextureTransColG32_SPR(unsigned long *pdest, unsigned long color);
    void GetTextureTransColGX_Dither(unsigned short *pdest, unsigned short color, long m1, long m2, long m3);
    void GetTextureTransColGX(unsigned short *pdest, unsigned short color, short m1, short m2, short m3);
    void GetTextureTransColGX_S(unsigned short *pdest, unsigned short color, short m1, short m2, short m3);
    void GetTextureTransColGX32_S(unsigned long *pdest, unsigned long color, short m1, short m2, short m3);
    void DrawSoftwareSprite_IL(unsigned char *baseAddr, short w, short h, long tx, long ty);
    void drawPoly3Fi(short x1, short y1, short x2, short y2, short x3, short y3, long rgb);
    void drawPoly3TD(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                     short ty2, short tx3, short ty3);
    void drawPoly3TEx4(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                       short ty2, short tx3, short ty3, short clX, short clY);
    void drawPoly3TEx4_IL(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                          short ty2, short tx3, short ty3, short clX, short clY);
    void drawPoly3TEx4_TW(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                          short ty2, short tx3, short ty3, short clX, short clY);
    void drawPoly4TEx4_TRI(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                           short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                           short clY);
    void drawPoly4TEx4(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                       short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                       short clY);
    void drawPoly4TEx4_IL(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                          short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                          short clY);
    void drawPoly4TEx4_TW(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                          short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                          short clY);
    void drawPoly4TEx4_TW_S(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                            short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                            short clY);
    void drawPoly3TEx8(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                       short ty2, short tx3, short ty3, short clX, short clY);
    void drawPoly3TEx8_IL(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                          short ty2, short tx3, short ty3, short clX, short clY);
    void drawPoly3TEx8_TW(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                          short ty2, short tx3, short ty3, short clX, short clY);
    void drawPoly4TEx8_TRI(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                           short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                           short clY);
    void drawPoly4TEx8(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                       short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                       short clY);
    void drawPoly4TEx8_IL(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                          short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                          short clY);
    void drawPoly4TEx8_TW(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                          short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                          short clY);
    void drawPoly4TEx8_TW_S(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                            short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                            short clY);
    void drawPoly3TD_TW(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                        short ty2, short tx3, short ty3);
    void drawPoly4TD_TRI(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                         short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4);
    void drawPoly4TD(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                     short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4);
    void drawPoly4TD_TW(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                        short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4);
    void drawPoly4TD_TW_S(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                          short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4);
    void drawPoly3Gi(short x1, short y1, short x2, short y2, short x3, short y3, long rgb1, long rgb2, long rgb3);
    void drawPoly3TGEx4(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                        short ty2, short tx3, short ty3, short clX, short clY, long col1, long col2, long col3);
    void drawPoly3TGEx4_IL(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                           short ty2, short tx3, short ty3, short clX, short clY, long col1, long col2, long col3);
    void drawPoly3TGEx4_TW(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                           short ty2, short tx3, short ty3, short clX, short clY, long col1, long col2, long col3);
    void drawPoly4TGEx4_TRI_IL(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4,
                               short tx1, short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4,
                               short clX, short clY, long col1, long col2, long col3, long col4);
    void drawPoly4TGEx4_TRI(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                            short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                            short clY, long col1, long col2, long col3, long col4);
    void drawPoly4TGEx4(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                        short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                        short clY, long col1, long col2, long col4, long col3);
    void drawPoly4TGEx4_TW(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                           short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                           short clY, long col1, long col2, long col3, long col4);
    void drawPoly3TGEx8(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                        short ty2, short tx3, short ty3, short clX, short clY, long col1, long col2, long col3);
    void drawPoly3TGEx8_IL(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                           short ty2, short tx3, short ty3, short clX, short clY, long col1, long col2, long col3);
    void drawPoly3TGEx8_TW(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                           short ty2, short tx3, short ty3, short clX, short clY, long col1, long col2, long col3);
    void drawPoly4TGEx8_TRI_IL(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4,
                               short tx1, short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4,
                               short clX, short clY, long col1, long col2, long col3, long col4);
    void drawPoly4TGEx8_TRI(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                            short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                            short clY, long col1, long col2, long col3, long col4);
    void drawPoly4TGEx8(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                        short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                        short clY, long col1, long col2, long col4, long col3);
    void drawPoly4TGEx8_TW(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                           short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, short clX,
                           short clY, long col1, long col2, long col3, long col4);
    void drawPoly3TGD(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                      short ty2, short tx3, short ty3, long col1, long col2, long col3);
    void drawPoly3TGD_TW(short x1, short y1, short x2, short y2, short x3, short y3, short tx1, short ty1, short tx2,
                         short ty2, short tx3, short ty3, long col1, long col2, long col3);
    void drawPoly4TGD_TRI(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                          short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, long col1,
                          long col2, long col3, long col4);
    void drawPoly4TGD(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                      short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, long col1, long col2,
                      long col4, long col3);
    void drawPoly4TGD_TW(short x1, short y1, short x2, short y2, short x3, short y3, short x4, short y4, short tx1,
                         short ty1, short tx2, short ty2, short tx3, short ty3, short tx4, short ty4, long col1,
                         long col2, long col3, long col4);
    void Line_E_SE_Shade(int x0, int y0, int x1, int y1, unsigned long rgb0, unsigned long rgb1);
    void Line_S_SE_Shade(int x0, int y0, int x1, int y1, unsigned long rgb0, unsigned long rgb1);
    void Line_N_NE_Shade(int x0, int y0, int x1, int y1, unsigned long rgb0, unsigned long rgb1);
    void Line_E_NE_Shade(int x0, int y0, int x1, int y1, unsigned long rgb0, unsigned long rgb1);
    void VertLineShade(int x, int y0, int y1, unsigned long rgb0, unsigned long rgb1);
    void HorzLineShade(int y, int x0, int x1, unsigned long rgb0, unsigned long rgb1);
    void Line_E_SE_Flat(int x0, int y0, int x1, int y1, unsigned short colour);
    void Line_S_SE_Flat(int x0, int y0, int x1, int y1, unsigned short colour);
    void Line_N_NE_Flat(int x0, int y0, int x1, int y1, unsigned short colour);
    void Line_E_NE_Flat(int x0, int y0, int x1, int y1, unsigned short colour);
    void VertLineFlat(int x, int y0, int y1, unsigned short colour);
    void HorzLineFlat(int y, int x0, int x1, unsigned short colour);
};

}  // namespace SoftGPU

}  // namespace PCSX
