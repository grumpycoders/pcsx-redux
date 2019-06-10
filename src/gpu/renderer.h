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

namespace PCSX {

namespace GPU {

class Renderer {
  protected:
    bool bUsingTWin = false;
    TWin_t TWin;
    uint16_t usMirror = 0;  // sprite mirror
    int iDither = 0;
    int drawX, drawY, drawW, drawH;

    bool DrawSemiTrans = false;
    int16_t g_m1 = 255, g_m2 = 255, g_m3 = 255;
    int16_t ly0, lx0, ly1, lx1, ly2, lx2, ly3, lx3;  // global psx vertex coords

    int32_t GlobalTextAddrX;
    int32_t GlobalTextAddrY;
    int32_t GlobalTextTP;
    int32_t GlobalTextABR;

    bool bCheckMask = false;
    uint16_t sSetMask = 0;
    uint32_t lSetMask = 0;

    void offsetPSXLine();
    void offsetPSX2();
    void offsetPSX3();
    void offsetPSX4();

    void FillSoftwareAreaTrans(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    void FillSoftwareArea(int16_t x0, int16_t y0, int16_t x1, int16_t y1, uint16_t col);
    void drawPoly3G(int32_t rgb1, int32_t rgb2, int32_t rgb3);
    void drawPoly4G(int32_t rgb1, int32_t rgb2, int32_t rgb3, int32_t rgb4);
    void drawPoly3F(int32_t rgb);
    void drawPoly4F(int32_t rgb);
    void drawPoly4FT(unsigned char *baseAddr);
    void drawPoly4GT(unsigned char *baseAddr);
    void drawPoly3FT(unsigned char *baseAddr);
    void drawPoly3GT(unsigned char *baseAddr);
    void DrawSoftwareSprite(unsigned char *baseAddr, int16_t w, int16_t h, int32_t tx, int32_t ty);
    void DrawSoftwareSpriteTWin(unsigned char *baseAddr, int32_t w, int32_t h);
    void DrawSoftwareSpriteMirror(unsigned char *baseAddr, int32_t w, int32_t h);
    void DrawSoftwareLineShade(int32_t rgb0, int32_t rgb1);
    void DrawSoftwareLineFlat(int32_t rgb);

    int16_t Ymin;
    int16_t Ymax;

    bool IsNoRect();

    bool SetupSections_F(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3);
    bool SetupSections_G(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb1, int32_t rgb2, int32_t rgb3);
    bool SetupSections_FT(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                          int16_t ty2, int16_t tx3, int16_t ty3);
    bool SetupSections_GT(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                          int16_t ty2, int16_t tx3, int16_t ty3, int32_t rgb1, int32_t rgb2, int32_t rgb3);
    bool SetupSections_F4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4);
    bool SetupSections_FT4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                           int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4);
    bool SetupSections_GT4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                           int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int32_t rgb1,
                           int32_t rgb2, int32_t rgb3, int32_t rgb4);

    void GetShadeTransCol_Dither(uint16_t *pdest, int32_t m1, int32_t m2, int32_t m3);
    void GetShadeTransCol(uint16_t *pdest, uint16_t color);
    void GetShadeTransCol32(uint32_t *pdest, uint32_t color);
    void GetTextureTransColG(uint16_t *pdest, uint16_t color);
    void GetTextureTransColG_S(uint16_t *pdest, uint16_t color);
    void GetTextureTransColG_SPR(uint16_t *pdest, uint16_t color);
    void GetTextureTransColG32(uint32_t *pdest, uint32_t color);
    void GetTextureTransColG32_S(uint32_t *pdest, uint32_t color);
    void GetTextureTransColG32_SPR(uint32_t *pdest, uint32_t color);
    void GetTextureTransColGX_Dither(uint16_t *pdest, uint16_t color, int32_t m1, int32_t m2, int32_t m3);
    void GetTextureTransColGX(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2, int16_t m3);
    void GetTextureTransColGX_S(uint16_t *pdest, uint16_t color, int16_t m1, int16_t m2, int16_t m3);
    void GetTextureTransColGX32_S(uint32_t *pdest, uint32_t color, int16_t m1, int16_t m2, int16_t m3);
    void DrawSoftwareSprite_IL(unsigned char *baseAddr, int16_t w, int16_t h, int32_t tx, int32_t ty);
    void drawPoly3Fi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb);
    void drawPoly3TD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                     int16_t ty2, int16_t tx3, int16_t ty3);
    void drawPoly3TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                       int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly3TEx4_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                          int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly3TEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                          int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly4TEx4_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                           int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                           int16_t clY);
    void drawPoly4TEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                       int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                       int16_t clY);
    void drawPoly4TEx4_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                          int16_t clY);
    void drawPoly4TEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                          int16_t clY);
    void drawPoly4TEx4_TW_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                            int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                            int16_t clY);
    void drawPoly3TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                       int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly3TEx8_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                          int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly3TEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                          int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY);
    void drawPoly4TEx8_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                           int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                           int16_t clY);
    void drawPoly4TEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                       int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                       int16_t clY);
    void drawPoly4TEx8_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                          int16_t clY);
    void drawPoly4TEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                          int16_t clY);
    void drawPoly4TEx8_TW_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                            int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                            int16_t clY);
    void drawPoly3TD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                        int16_t ty2, int16_t tx3, int16_t ty3);
    void drawPoly4TD_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                         int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4);
    void drawPoly4TD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                     int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4);
    void drawPoly4TD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                        int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4);
    void drawPoly4TD_TW_S(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4);
    void drawPoly3Gi(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int32_t rgb1, int32_t rgb2, int32_t rgb3);
    void drawPoly3TGEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                        int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly3TGEx4_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                           int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly3TGEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                           int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly4TGEx4_TRI_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                               int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                               int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly4TGEx4_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                            int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                            int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly4TGEx4(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                        int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                        int16_t clY, int32_t col1, int32_t col2, int32_t col4, int32_t col3);
    void drawPoly4TGEx4_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                           int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                           int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly3TGEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                        int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly3TGEx8_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                           int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly3TGEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                           int16_t ty2, int16_t tx3, int16_t ty3, int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly4TGEx8_TRI_IL(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4,
                               int16_t tx1, int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4,
                               int16_t clX, int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly4TGEx8_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                            int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                            int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly4TGEx8(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                        int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                        int16_t clY, int32_t col1, int32_t col2, int32_t col4, int32_t col3);
    void drawPoly4TGEx8_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                           int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int16_t clX,
                           int16_t clY, int32_t col1, int32_t col2, int32_t col3, int32_t col4);
    void drawPoly3TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                      int16_t ty2, int16_t tx3, int16_t ty3, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly3TGD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t tx1, int16_t ty1, int16_t tx2,
                         int16_t ty2, int16_t tx3, int16_t ty3, int32_t col1, int32_t col2, int32_t col3);
    void drawPoly4TGD_TRI(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                          int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int32_t col1,
                          int32_t col2, int32_t col3, int32_t col4);
    void drawPoly4TGD(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                      int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int32_t col1, int32_t col2,
                      int32_t col4, int32_t col3);
    void drawPoly4TGD_TW(int16_t x1, int16_t y1, int16_t x2, int16_t y2, int16_t x3, int16_t y3, int16_t x4, int16_t y4, int16_t tx1,
                         int16_t ty1, int16_t tx2, int16_t ty2, int16_t tx3, int16_t ty3, int16_t tx4, int16_t ty4, int32_t col1,
                         int32_t col2, int32_t col3, int32_t col4);
    void Line_E_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void Line_S_SE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void Line_N_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void Line_E_NE_Shade(int x0, int y0, int x1, int y1, uint32_t rgb0, uint32_t rgb1);
    void VertLineShade(int x, int y0, int y1, uint32_t rgb0, uint32_t rgb1);
    void HorzLineShade(int y, int x0, int x1, uint32_t rgb0, uint32_t rgb1);
    void Line_E_SE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void Line_S_SE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void Line_N_NE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void Line_E_NE_Flat(int x0, int y0, int x1, int y1, uint16_t colour);
    void VertLineFlat(int x, int y0, int y1, uint16_t colour);
    void HorzLineFlat(int y, int x0, int x1, uint16_t colour);
};

}  // namespace GPU

}  // namespace PCSX
