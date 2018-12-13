/***************************************************************************
                          draw.c  -  description
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

#define _IN_DRAW

#include "draw.h"
#include "externals.h"
#include "gpu.h"
#include "interp.h"
#include "menu.h"
#include "prim.h"

////////////////////////////////////////////////////////////////////////////////////
// misc globals
////////////////////////////////////////////////////////////////////////////////////

int iResX;
int iResY;
long lLowerpart;
BOOL bIsFirstFrame = TRUE;
BOOL bCheckMask = FALSE;
unsigned short sSetMask = 0;
unsigned long lSetMask = 0;
int iDesktopCol = 16;
int iShowFPS = 0;
int iWinSize;
int iUseScanLines = 0;
int iUseNoStretchBlt = 0;
int iFastFwd = 0;
int iDebugMode = 0;
int iFVDisplay = 0;
PSXPoint_t ptCursorPoint[8];
unsigned short usCursorActive = 0;

unsigned int LUT16to32[65536];
unsigned int RGBtoYUV[65536];

// prototypes
void hq2x_32(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height);
void hq2x(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height);
void hq3x_16(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height);
void hq3x_32(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height);

////////////////////////////////////////////////////////////////////////
// generic 2xSaI helpers
////////////////////////////////////////////////////////////////////////

void *pSaISmallBuff = NULL;
void *pSaIBigBuff = NULL;

#define GET_RESULT(A, B, C, D) ((A != C || A != D) - (B != C || B != D))

static __inline int GetResult1(DWORD A, DWORD B, DWORD C, DWORD D, DWORD E) {
    int x = 0;
    int y = 0;
    int r = 0;
    if (A == C)
        x += 1;
    else if (B == C)
        y += 1;
    if (A == D)
        x += 1;
    else if (B == D)
        y += 1;
    if (x <= 1) r += 1;
    if (y <= 1) r -= 1;
    return r;
}

static __inline int GetResult2(DWORD A, DWORD B, DWORD C, DWORD D, DWORD E) {
    int x = 0;
    int y = 0;
    int r = 0;
    if (A == C)
        x += 1;
    else if (B == C)
        y += 1;
    if (A == D)
        x += 1;
    else if (B == D)
        y += 1;
    if (x <= 1) r -= 1;
    if (y <= 1) r += 1;
    return r;
}

#define colorMask8 0x00FEFEFE
#define lowPixelMask8 0x00010101
#define qcolorMask8 0x00FCFCFC
#define qlowpixelMask8 0x00030303

#define INTERPOLATE8(A, B) ((((A & colorMask8) >> 1) + ((B & colorMask8) >> 1) + (A & B & lowPixelMask8)))
#define Q_INTERPOLATE8(A, B, C, D)                                                                                 \
    (((((A & qcolorMask8) >> 2) + ((B & qcolorMask8) >> 2) + ((C & qcolorMask8) >> 2) + ((D & qcolorMask8) >> 2) + \
       ((((A & qlowpixelMask8) + (B & qlowpixelMask8) + (C & qlowpixelMask8) + (D & qlowpixelMask8)) >> 2) &       \
        qlowpixelMask8))))

void Super2xSaI_ex8(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    DWORD srcPitchHalf = srcPitch >> 1;
    int finWidth = srcPitch >> 2;
    DWORD line;
    DWORD *dP;
    DWORD *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;
    DWORD color4, color5, color6;
    DWORD color1, color2, color3;
    DWORD colorA0, colorA1, colorA2, colorA3, colorB0, colorB1, colorB2, colorB3, colorS1, colorS2;
    DWORD product1a, product1b, product2a, product2b;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (DWORD *)srcPtr;
            dP = (DWORD *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                //---------------------------------------    B1 B2
                //                                         4  5  6 S2
                //                                         1  2  3 S1
                //                                           A1 A2
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0) {
                    iYA = 0;
                } else {
                    iYA = finWidth;
                }
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitchHalf;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorB0 = *(bP - iYA - iXA);
                colorB1 = *(bP - iYA);
                colorB2 = *(bP - iYA + iXB);
                colorB3 = *(bP - iYA + iXC);

                color4 = *(bP - iXA);
                color5 = *(bP);
                color6 = *(bP + iXB);
                colorS2 = *(bP + iXC);

                color1 = *(bP + iYB - iXA);
                color2 = *(bP + iYB);
                color3 = *(bP + iYB + iXB);
                colorS1 = *(bP + iYB + iXC);

                colorA0 = *(bP + iYC - iXA);
                colorA1 = *(bP + iYC);
                colorA2 = *(bP + iYC + iXB);
                colorA3 = *(bP + iYC + iXC);

                if (color2 == color6 && color5 != color3) {
                    product2b = product1b = color2;
                } else if (color5 == color3 && color2 != color6) {
                    product2b = product1b = color5;
                } else if (color5 == color3 && color2 == color6) {
                    register int r = 0;

                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (color1 & 0x00ffffff),
                                    (colorA1 & 0x00ffffff));
                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (color4 & 0x00ffffff),
                                    (colorB1 & 0x00ffffff));
                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (colorA2 & 0x00ffffff),
                                    (colorS1 & 0x00ffffff));
                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (colorB2 & 0x00ffffff),
                                    (colorS2 & 0x00ffffff));

                    if (r > 0)
                        product2b = product1b = color6;
                    else if (r < 0)
                        product2b = product1b = color5;
                    else {
                        product2b = product1b = INTERPOLATE8(color5, color6);
                    }
                } else {
                    if (color6 == color3 && color3 == colorA1 && color2 != colorA2 && color3 != colorA0)
                        product2b = Q_INTERPOLATE8(color3, color3, color3, color2);
                    else if (color5 == color2 && color2 == colorA2 && colorA1 != color3 && color2 != colorA3)
                        product2b = Q_INTERPOLATE8(color2, color2, color2, color3);
                    else
                        product2b = INTERPOLATE8(color2, color3);

                    if (color6 == color3 && color6 == colorB1 && color5 != colorB2 && color6 != colorB0)
                        product1b = Q_INTERPOLATE8(color6, color6, color6, color5);
                    else if (color5 == color2 && color5 == colorB2 && colorB1 != color6 && color5 != colorB3)
                        product1b = Q_INTERPOLATE8(color6, color5, color5, color5);
                    else
                        product1b = INTERPOLATE8(color5, color6);
                }

                if (color5 == color3 && color2 != color6 && color4 == color5 && color5 != colorA2)
                    product2a = INTERPOLATE8(color2, color5);
                else if (color5 == color1 && color6 == color5 && color4 != color2 && color5 != colorA0)
                    product2a = INTERPOLATE8(color2, color5);
                else
                    product2a = color2;

                if (color2 == color6 && color5 != color3 && color1 == color2 && color2 != colorB2)
                    product1a = INTERPOLATE8(color2, color5);
                else if (color4 == color2 && color3 == color2 && color1 != color5 && color2 != colorB0)
                    product1a = INTERPOLATE8(color2, color5);
                else
                    product1a = color5;

                *dP = product1a;
                *(dP + 1) = product1b;
                *(dP + (srcPitchHalf)) = product2a;
                *(dP + 1 + (srcPitchHalf)) = product2b;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////

void Std2xSaI_ex8(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    DWORD srcPitchHalf = srcPitch >> 1;
    int finWidth = srcPitch >> 2;
    DWORD line;
    DWORD *dP;
    DWORD *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;

    DWORD colorA, colorB;
    DWORD colorC, colorD, colorE, colorF, colorG, colorH, colorI, colorJ, colorK, colorL, colorM, colorN, colorO,
        colorP;
    DWORD product, product1, product2;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (DWORD *)srcPtr;
            dP = (DWORD *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                //---------------------------------------
                // Map of the pixels:                    I|E F|J
                //                                       G|A B|K
                //                                       H|C D|L
                //                                       M|N O|P
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0) {
                    iYA = 0;
                } else {
                    iYA = finWidth;
                }
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitchHalf;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorI = *(bP - iYA - iXA);
                colorE = *(bP - iYA);
                colorF = *(bP - iYA + iXB);
                colorJ = *(bP - iYA + iXC);

                colorG = *(bP - iXA);
                colorA = *(bP);
                colorB = *(bP + iXB);
                colorK = *(bP + iXC);

                colorH = *(bP + iYB - iXA);
                colorC = *(bP + iYB);
                colorD = *(bP + iYB + iXB);
                colorL = *(bP + iYB + iXC);

                colorM = *(bP + iYC - iXA);
                colorN = *(bP + iYC);
                colorO = *(bP + iYC + iXB);
                colorP = *(bP + iYC + iXC);

                if ((colorA == colorD) && (colorB != colorC)) {
                    if (((colorA == colorE) && (colorB == colorL)) ||
                        ((colorA == colorC) && (colorA == colorF) && (colorB != colorE) && (colorB == colorJ))) {
                        product = colorA;
                    } else {
                        product = INTERPOLATE8(colorA, colorB);
                    }

                    if (((colorA == colorG) && (colorC == colorO)) ||
                        ((colorA == colorB) && (colorA == colorH) && (colorG != colorC) && (colorC == colorM))) {
                        product1 = colorA;
                    } else {
                        product1 = INTERPOLATE8(colorA, colorC);
                    }
                    product2 = colorA;
                } else if ((colorB == colorC) && (colorA != colorD)) {
                    if (((colorB == colorF) && (colorA == colorH)) ||
                        ((colorB == colorE) && (colorB == colorD) && (colorA != colorF) && (colorA == colorI))) {
                        product = colorB;
                    } else {
                        product = INTERPOLATE8(colorA, colorB);
                    }

                    if (((colorC == colorH) && (colorA == colorF)) ||
                        ((colorC == colorG) && (colorC == colorD) && (colorA != colorH) && (colorA == colorI))) {
                        product1 = colorC;
                    } else {
                        product1 = INTERPOLATE8(colorA, colorC);
                    }
                    product2 = colorB;
                } else if ((colorA == colorD) && (colorB == colorC)) {
                    if (colorA == colorB) {
                        product = colorA;
                        product1 = colorA;
                        product2 = colorA;
                    } else {
                        register int r = 0;
                        product1 = INTERPOLATE8(colorA, colorC);
                        product = INTERPOLATE8(colorA, colorB);

                        r += GetResult1(colorA & 0x00FFFFFF, colorB & 0x00FFFFFF, colorG & 0x00FFFFFF,
                                        colorE & 0x00FFFFFF, colorI & 0x00FFFFFF);
                        r += GetResult2(colorB & 0x00FFFFFF, colorA & 0x00FFFFFF, colorK & 0x00FFFFFF,
                                        colorF & 0x00FFFFFF, colorJ & 0x00FFFFFF);
                        r += GetResult2(colorB & 0x00FFFFFF, colorA & 0x00FFFFFF, colorH & 0x00FFFFFF,
                                        colorN & 0x00FFFFFF, colorM & 0x00FFFFFF);
                        r += GetResult1(colorA & 0x00FFFFFF, colorB & 0x00FFFFFF, colorL & 0x00FFFFFF,
                                        colorO & 0x00FFFFFF, colorP & 0x00FFFFFF);

                        if (r > 0)
                            product2 = colorA;
                        else if (r < 0)
                            product2 = colorB;
                        else {
                            product2 = Q_INTERPOLATE8(colorA, colorB, colorC, colorD);
                        }
                    }
                } else {
                    product2 = Q_INTERPOLATE8(colorA, colorB, colorC, colorD);

                    if ((colorA == colorC) && (colorA == colorF) && (colorB != colorE) && (colorB == colorJ)) {
                        product = colorA;
                    } else if ((colorB == colorE) && (colorB == colorD) && (colorA != colorF) && (colorA == colorI)) {
                        product = colorB;
                    } else {
                        product = INTERPOLATE8(colorA, colorB);
                    }

                    if ((colorA == colorB) && (colorA == colorH) && (colorG != colorC) && (colorC == colorM)) {
                        product1 = colorA;
                    } else if ((colorC == colorG) && (colorC == colorD) && (colorA != colorH) && (colorA == colorI)) {
                        product1 = colorC;
                    } else {
                        product1 = INTERPOLATE8(colorA, colorC);
                    }
                }

                //////////////////////////

                *dP = colorA;
                *(dP + 1) = product;
                *(dP + (srcPitchHalf)) = product1;
                *(dP + 1 + (srcPitchHalf)) = product2;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////

void SuperEagle_ex8(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    DWORD srcPitchHalf = srcPitch >> 1;
    int finWidth = srcPitch >> 2;
    DWORD line;
    DWORD *dP;
    DWORD *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;
    DWORD color4, color5, color6;
    DWORD color1, color2, color3;
    DWORD colorA1, colorA2, colorB1, colorB2, colorS1, colorS2;
    DWORD product1a, product1b, product2a, product2b;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (DWORD *)srcPtr;
            dP = (DWORD *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0) {
                    iYA = 0;
                } else {
                    iYA = finWidth;
                }
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitchHalf;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorB1 = *(bP - iYA);
                colorB2 = *(bP - iYA + iXB);

                color4 = *(bP - iXA);
                color5 = *(bP);
                color6 = *(bP + iXB);
                colorS2 = *(bP + iXC);

                color1 = *(bP + iYB - iXA);
                color2 = *(bP + iYB);
                color3 = *(bP + iYB + iXB);
                colorS1 = *(bP + iYB + iXC);

                colorA1 = *(bP + iYC);
                colorA2 = *(bP + iYC + iXB);

                if (color2 == color6 && color5 != color3) {
                    product1b = product2a = color2;
                    if ((color1 == color2) || (color6 == colorB2)) {
                        product1a = INTERPOLATE8(color2, color5);
                        product1a = INTERPOLATE8(color2, product1a);
                    } else {
                        product1a = INTERPOLATE8(color5, color6);
                    }

                    if ((color6 == colorS2) || (color2 == colorA1)) {
                        product2b = INTERPOLATE8(color2, color3);
                        product2b = INTERPOLATE8(color2, product2b);
                    } else {
                        product2b = INTERPOLATE8(color2, color3);
                    }
                } else if (color5 == color3 && color2 != color6) {
                    product2b = product1a = color5;

                    if ((colorB1 == color5) || (color3 == colorS1)) {
                        product1b = INTERPOLATE8(color5, color6);
                        product1b = INTERPOLATE8(color5, product1b);
                    } else {
                        product1b = INTERPOLATE8(color5, color6);
                    }

                    if ((color3 == colorA2) || (color4 == color5)) {
                        product2a = INTERPOLATE8(color5, color2);
                        product2a = INTERPOLATE8(color5, product2a);
                    } else {
                        product2a = INTERPOLATE8(color2, color3);
                    }
                } else if (color5 == color3 && color2 == color6) {
                    register int r = 0;

                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (color1 & 0x00ffffff),
                                    (colorA1 & 0x00ffffff));
                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (color4 & 0x00ffffff),
                                    (colorB1 & 0x00ffffff));
                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (colorA2 & 0x00ffffff),
                                    (colorS1 & 0x00ffffff));
                    r += GET_RESULT((color6 & 0x00ffffff), (color5 & 0x00ffffff), (colorB2 & 0x00ffffff),
                                    (colorS2 & 0x00ffffff));

                    if (r > 0) {
                        product1b = product2a = color2;
                        product1a = product2b = INTERPOLATE8(color5, color6);
                    } else if (r < 0) {
                        product2b = product1a = color5;
                        product1b = product2a = INTERPOLATE8(color5, color6);
                    } else {
                        product2b = product1a = color5;
                        product1b = product2a = color2;
                    }
                } else {
                    product2b = product1a = INTERPOLATE8(color2, color6);
                    product2b = Q_INTERPOLATE8(color3, color3, color3, product2b);
                    product1a = Q_INTERPOLATE8(color5, color5, color5, product1a);

                    product2a = product1b = INTERPOLATE8(color5, color3);
                    product2a = Q_INTERPOLATE8(color2, color2, color2, product2a);
                    product1b = Q_INTERPOLATE8(color6, color6, color6, product1b);
                }

                ////////////////////////////////

                *dP = product1a;
                *(dP + 1) = product1b;
                *(dP + (srcPitchHalf)) = product2a;
                *(dP + 1 + (srcPitchHalf)) = product2b;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

/////////////////////////

static __inline void scale2x_32_def_whole(unsigned long *dst0, unsigned long *dst1, const unsigned long *src0,
                                          const unsigned long *src1, const unsigned long *src2, unsigned count) {
    // first pixel
    if (src0[0] != src2[0] && src1[0] != src1[1]) {
        dst0[0] = src1[0] == src0[0] ? src0[0] : src1[0];
        dst0[1] = src1[1] == src0[0] ? src0[0] : src1[0];
        dst1[0] = src1[0] == src2[0] ? src2[0] : src1[0];
        dst1[1] = src1[1] == src2[0] ? src2[0] : src1[0];
    } else {
        dst0[0] = src1[0];
        dst0[1] = src1[0];
        dst1[0] = src1[0];
        dst1[1] = src1[0];
    }
    ++src0;
    ++src1;
    ++src2;
    dst0 += 2;
    dst1 += 2;

    // central pixels
    count -= 2;
    while (count) {
        if (src0[0] != src2[0] && src1[-1] != src1[1]) {
            dst0[0] = src1[-1] == src0[0] ? src0[0] : src1[0];
            dst0[1] = src1[1] == src0[0] ? src0[0] : src1[0];
            dst1[0] = src1[-1] == src2[0] ? src2[0] : src1[0];
            dst1[1] = src1[1] == src2[0] ? src2[0] : src1[0];
        } else {
            dst0[0] = src1[0];
            dst0[1] = src1[0];
            dst1[0] = src1[0];
            dst1[1] = src1[0];
        }

        ++src0;
        ++src1;
        ++src2;
        dst0 += 2;
        dst1 += 2;
        --count;
    }

    // last pixel
    if (src0[0] != src2[0] && src1[-1] != src1[0]) {
        dst0[0] = src1[-1] == src0[0] ? src0[0] : src1[0];
        dst0[1] = src1[0] == src0[0] ? src0[0] : src1[0];
        dst1[0] = src1[-1] == src2[0] ? src2[0] : src1[0];
        dst1[1] = src1[0] == src2[0] ? src2[0] : src1[0];
    } else {
        dst0[0] = src1[0];
        dst0[1] = src1[0];
        dst1[0] = src1[0];
        dst1[1] = src1[0];
    }
}

void Scale2x_ex8(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height) {
    const int dstPitch = srcPitch << 1;

    int count = height;

    unsigned long *dst0 = (unsigned long *)dstPtr;
    unsigned long *dst1 = dst0 + (dstPitch >> 2);

    unsigned long *src0 = (unsigned long *)srcPtr;
    unsigned long *src1 = src0 + (srcPitch >> 2);
    unsigned long *src2 = src1 + (srcPitch >> 2);
    scale2x_32_def_whole(dst0, dst1, src0, src0, src1, width);

    count -= 2;
    while (count) {
        dst0 += dstPitch >> 1;
        dst1 += dstPitch >> 1;
        scale2x_32_def_whole(dst0, dst1, src0, src0, src1, width);
        src0 = src1;
        src1 = src2;
        src2 += srcPitch >> 2;
        --count;
    }
    dst0 += dstPitch >> 1;
    dst1 += dstPitch >> 1;
    scale2x_32_def_whole(dst0, dst1, src0, src1, src1, width);
}

////////////////////////////////////////////////////////////////////////

static __inline void scale3x_32_def_whole(unsigned long *dst0, unsigned long *dst1, unsigned long *dst2,
                                          const unsigned long *src0, const unsigned long *src1,
                                          const unsigned long *src2, unsigned count) {
    // first pixel
    if (src0[0] != src2[0] && src1[0] != src1[1]) {
        dst0[0] = src1[0];
        dst0[1] = (src1[0] == src0[0] && src1[0] != src0[1]) || (src1[1] == src0[0] && src1[0] != src0[0]) ? src0[0]
                                                                                                           : src1[0];
        dst0[2] = src1[1] == src0[0] ? src1[1] : src1[0];
        dst1[0] = (src1[0] == src0[0] && src1[0] != src2[0]) || (src1[0] == src2[0] && src1[0] != src0[0]) ? src1[0]
                                                                                                           : src1[0];
        dst1[1] = src1[0];
        dst1[2] = (src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1]) ? src1[1]
                                                                                                           : src1[0];
        dst2[0] = src1[0];
        dst2[1] = (src1[0] == src2[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src2[0]) ? src2[0]
                                                                                                           : src1[0];
        dst2[2] = src1[1] == src2[0] ? src1[1] : src1[0];
    } else {
        dst0[0] = src1[0];
        dst0[1] = src1[0];
        dst0[2] = src1[0];
        dst1[0] = src1[0];
        dst1[1] = src1[0];
        dst1[2] = src1[0];
        dst2[0] = src1[0];
        dst2[1] = src1[0];
        dst2[2] = src1[0];
    }
    ++src0;
    ++src1;
    ++src2;
    dst0 += 3;
    dst1 += 3;
    dst2 += 3;

    // central pixels
    count -= 2;
    while (count) {
        if (src0[0] != src2[0] && src1[-1] != src1[1]) {
            dst0[0] = src1[-1] == src0[0] ? src1[-1] : src1[0];
            dst0[1] = (src1[-1] == src0[0] && src1[0] != src0[1]) || (src1[1] == src0[0] && src1[0] != src0[-1])
                          ? src0[0]
                          : src1[0];
            dst0[2] = src1[1] == src0[0] ? src1[1] : src1[0];
            dst1[0] = (src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1])
                          ? src1[-1]
                          : src1[0];
            dst1[1] = src1[0];
            dst1[2] = (src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1])
                          ? src1[1]
                          : src1[0];
            dst2[0] = src1[-1] == src2[0] ? src1[-1] : src1[0];
            dst2[1] = (src1[-1] == src2[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src2[-1])
                          ? src2[0]
                          : src1[0];
            dst2[2] = src1[1] == src2[0] ? src1[1] : src1[0];
        } else {
            dst0[0] = src1[0];
            dst0[1] = src1[0];
            dst0[2] = src1[0];
            dst1[0] = src1[0];
            dst1[1] = src1[0];
            dst1[2] = src1[0];
            dst2[0] = src1[0];
            dst2[1] = src1[0];
            dst2[2] = src1[0];
        }

        ++src0;
        ++src1;
        ++src2;
        dst0 += 3;
        dst1 += 3;
        dst2 += 3;
        --count;
    }

    // last pixel
    if (src0[0] != src2[0] && src1[-1] != src1[0]) {
        dst0[0] = src1[-1] == src0[0] ? src1[-1] : src1[0];
        dst0[1] = (src1[-1] == src0[0] && src1[0] != src0[0]) || (src1[0] == src0[0] && src1[0] != src0[-1]) ? src0[0]
                                                                                                             : src1[0];
        dst0[2] = src1[0];
        dst1[0] = (src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1])
                      ? src1[-1]
                      : src1[0];
        dst1[1] = src1[0];
        dst1[2] = (src1[0] == src0[0] && src1[0] != src2[0]) || (src1[0] == src2[0] && src1[0] != src0[0]) ? src1[0]
                                                                                                           : src1[0];
        dst2[0] = src1[-1] == src2[0] ? src1[-1] : src1[0];
        dst2[1] = (src1[-1] == src2[0] && src1[0] != src2[0]) || (src1[0] == src2[0] && src1[0] != src2[-1]) ? src2[0]
                                                                                                             : src1[0];
        dst2[2] = src1[0];
    } else {
        dst0[0] = src1[0];
        dst0[1] = src1[0];
        dst0[2] = src1[0];
        dst1[0] = src1[0];
        dst1[1] = src1[0];
        dst1[2] = src1[0];
        dst2[0] = src1[0];
        dst2[1] = src1[0];
        dst2[2] = src1[0];
    }
}

void Scale3x_ex8(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height) {
    int count = height;

    int dstPitch = srcPitch >> 1;

    unsigned long *dst0 = (unsigned long *)dstPtr;
    unsigned long *dst1 = dst0 + dstPitch;
    unsigned long *dst2 = dst1 + dstPitch;

    unsigned long *src0 = (unsigned long *)srcPtr;
    unsigned long *src1 = src0 + (srcPitch >> 2);
    unsigned long *src2 = src1 + (srcPitch >> 2);
    scale3x_32_def_whole(dst0, dst1, dst2, src0, src0, src2, width);

    count -= 2;
    while (count) {
        dst0 += dstPitch * 3;
        dst1 += dstPitch * 3;
        dst2 += dstPitch * 3;

        scale3x_32_def_whole(dst0, dst1, dst2, src0, src1, src2, width);
        src0 = src1;
        src1 = src2;
        src2 += srcPitch >> 2;
        --count;
    }
    dst0 += dstPitch * 3;
    dst1 += dstPitch * 3;
    dst2 += dstPitch * 3;

    scale3x_32_def_whole(dst0, dst1, dst2, src0, src1, src1, width);
}

////////////////////////////////////////////////////////////////////////

#define colorMask6 0x0000F7DE
#define lowPixelMask6 0x00000821
#define qcolorMask6 0x0000E79c
#define qlowpixelMask6 0x00001863

#define INTERPOLATE6(A, B) ((((A & colorMask6) >> 1) + ((B & colorMask6) >> 1) + (A & B & lowPixelMask6)))
#define Q_INTERPOLATE6(A, B, C, D)                                                                                 \
    (((((A & qcolorMask6) >> 2) + ((B & qcolorMask6) >> 2) + ((C & qcolorMask6) >> 2) + ((D & qcolorMask6) >> 2) + \
       ((((A & qlowpixelMask6) + (B & qlowpixelMask6) + (C & qlowpixelMask6) + (D & qlowpixelMask6)) >> 2) &       \
        qlowpixelMask6))))

void Super2xSaI_ex6(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    int finWidth = srcPitch >> 1;
    DWORD line;
    unsigned short *dP;
    unsigned short *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;
    DWORD color4, color5, color6;
    DWORD color1, color2, color3;
    DWORD colorA0, colorA1, colorA2, colorA3, colorB0, colorB1, colorB2, colorB3, colorS1, colorS2;
    DWORD product1a, product1b, product2a, product2b;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (unsigned short *)srcPtr;
            dP = (unsigned short *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                //---------------------------------------    B1 B2
                //                                         4  5  6 S2
                //                                         1  2  3 S1
                //                                           A1 A2
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0)
                    iYA = 0;
                else
                    iYA = finWidth;
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitch;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorB0 = *(bP - iYA - iXA);
                colorB1 = *(bP - iYA);
                colorB2 = *(bP - iYA + iXB);
                colorB3 = *(bP - iYA + iXC);

                color4 = *(bP - iXA);
                color5 = *(bP);
                color6 = *(bP + iXB);
                colorS2 = *(bP + iXC);

                color1 = *(bP + iYB - iXA);
                color2 = *(bP + iYB);
                color3 = *(bP + iYB + iXB);
                colorS1 = *(bP + iYB + iXC);

                colorA0 = *(bP + iYC - iXA);
                colorA1 = *(bP + iYC);
                colorA2 = *(bP + iYC + iXB);
                colorA3 = *(bP + iYC + iXC);

                //--------------------------------------
                if (color2 == color6 && color5 != color3) {
                    product2b = product1b = color2;
                } else if (color5 == color3 && color2 != color6) {
                    product2b = product1b = color5;
                } else if (color5 == color3 && color2 == color6) {
                    register int r = 0;

                    r += GET_RESULT((color6), (color5), (color1), (colorA1));
                    r += GET_RESULT((color6), (color5), (color4), (colorB1));
                    r += GET_RESULT((color6), (color5), (colorA2), (colorS1));
                    r += GET_RESULT((color6), (color5), (colorB2), (colorS2));

                    if (r > 0)
                        product2b = product1b = color6;
                    else if (r < 0)
                        product2b = product1b = color5;
                    else {
                        product2b = product1b = INTERPOLATE6(color5, color6);
                    }
                } else {
                    if (color6 == color3 && color3 == colorA1 && color2 != colorA2 && color3 != colorA0)
                        product2b = Q_INTERPOLATE6(color3, color3, color3, color2);
                    else if (color5 == color2 && color2 == colorA2 && colorA1 != color3 && color2 != colorA3)
                        product2b = Q_INTERPOLATE6(color2, color2, color2, color3);
                    else
                        product2b = INTERPOLATE6(color2, color3);

                    if (color6 == color3 && color6 == colorB1 && color5 != colorB2 && color6 != colorB0)
                        product1b = Q_INTERPOLATE6(color6, color6, color6, color5);
                    else if (color5 == color2 && color5 == colorB2 && colorB1 != color6 && color5 != colorB3)
                        product1b = Q_INTERPOLATE6(color6, color5, color5, color5);
                    else
                        product1b = INTERPOLATE6(color5, color6);
                }

                if (color5 == color3 && color2 != color6 && color4 == color5 && color5 != colorA2)
                    product2a = INTERPOLATE6(color2, color5);
                else if (color5 == color1 && color6 == color5 && color4 != color2 && color5 != colorA0)
                    product2a = INTERPOLATE6(color2, color5);
                else
                    product2a = color2;

                if (color2 == color6 && color5 != color3 && color1 == color2 && color2 != colorB2)
                    product1a = INTERPOLATE6(color2, color5);
                else if (color4 == color2 && color3 == color2 && color1 != color5 && color2 != colorB0)
                    product1a = INTERPOLATE6(color2, color5);
                else
                    product1a = color5;

                *dP = (unsigned short)product1a;
                *(dP + 1) = (unsigned short)product1b;
                *(dP + (srcPitch)) = (unsigned short)product2a;
                *(dP + 1 + (srcPitch)) = (unsigned short)product2b;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////

void Std2xSaI_ex6(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    int finWidth = srcPitch >> 1;
    DWORD line;
    unsigned short *dP;
    unsigned short *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;

    DWORD colorA, colorB;
    DWORD colorC, colorD, colorE, colorF, colorG, colorH, colorI, colorJ, colorK, colorL, colorM, colorN, colorO,
        colorP;
    DWORD product, product1, product2;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (unsigned short *)srcPtr;
            dP = (unsigned short *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                //---------------------------------------
                // Map of the pixels:                    I|E F|J
                //                                       G|A B|K
                //                                       H|C D|L
                //                                       M|N O|P
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0)
                    iYA = 0;
                else
                    iYA = finWidth;
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitch;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorI = *(bP - iYA - iXA);
                colorE = *(bP - iYA);
                colorF = *(bP - iYA + iXB);
                colorJ = *(bP - iYA + iXC);

                colorG = *(bP - iXA);
                colorA = *(bP);
                colorB = *(bP + iXB);
                colorK = *(bP + iXC);

                colorH = *(bP + iYB - iXA);
                colorC = *(bP + iYB);
                colorD = *(bP + iYB + iXB);
                colorL = *(bP + iYB + iXC);

                colorM = *(bP + iYC - iXA);
                colorN = *(bP + iYC);
                colorO = *(bP + iYC + iXB);
                colorP = *(bP + iYC + iXC);

                if ((colorA == colorD) && (colorB != colorC)) {
                    if (((colorA == colorE) && (colorB == colorL)) ||
                        ((colorA == colorC) && (colorA == colorF) && (colorB != colorE) && (colorB == colorJ))) {
                        product = colorA;
                    } else {
                        product = INTERPOLATE6(colorA, colorB);
                    }

                    if (((colorA == colorG) && (colorC == colorO)) ||
                        ((colorA == colorB) && (colorA == colorH) && (colorG != colorC) && (colorC == colorM))) {
                        product1 = colorA;
                    } else {
                        product1 = INTERPOLATE6(colorA, colorC);
                    }
                    product2 = colorA;
                } else if ((colorB == colorC) && (colorA != colorD)) {
                    if (((colorB == colorF) && (colorA == colorH)) ||
                        ((colorB == colorE) && (colorB == colorD) && (colorA != colorF) && (colorA == colorI))) {
                        product = colorB;
                    } else {
                        product = INTERPOLATE6(colorA, colorB);
                    }

                    if (((colorC == colorH) && (colorA == colorF)) ||
                        ((colorC == colorG) && (colorC == colorD) && (colorA != colorH) && (colorA == colorI))) {
                        product1 = colorC;
                    } else {
                        product1 = INTERPOLATE6(colorA, colorC);
                    }
                    product2 = colorB;
                } else if ((colorA == colorD) && (colorB == colorC)) {
                    if (colorA == colorB) {
                        product = colorA;
                        product1 = colorA;
                        product2 = colorA;
                    } else {
                        register int r = 0;
                        product1 = INTERPOLATE6(colorA, colorC);
                        product = INTERPOLATE6(colorA, colorB);

                        r += GetResult1(colorA, colorB, colorG, colorE, colorI);
                        r += GetResult2(colorB, colorA, colorK, colorF, colorJ);
                        r += GetResult2(colorB, colorA, colorH, colorN, colorM);
                        r += GetResult1(colorA, colorB, colorL, colorO, colorP);

                        if (r > 0)
                            product2 = colorA;
                        else if (r < 0)
                            product2 = colorB;
                        else {
                            product2 = Q_INTERPOLATE6(colorA, colorB, colorC, colorD);
                        }
                    }
                } else {
                    product2 = Q_INTERPOLATE6(colorA, colorB, colorC, colorD);

                    if ((colorA == colorC) && (colorA == colorF) && (colorB != colorE) && (colorB == colorJ)) {
                        product = colorA;
                    } else if ((colorB == colorE) && (colorB == colorD) && (colorA != colorF) && (colorA == colorI)) {
                        product = colorB;
                    } else {
                        product = INTERPOLATE6(colorA, colorB);
                    }

                    if ((colorA == colorB) && (colorA == colorH) && (colorG != colorC) && (colorC == colorM)) {
                        product1 = colorA;
                    } else if ((colorC == colorG) && (colorC == colorD) && (colorA != colorH) && (colorA == colorI)) {
                        product1 = colorC;
                    } else {
                        product1 = INTERPOLATE6(colorA, colorC);
                    }
                }

                *dP = (unsigned short)colorA;
                *(dP + 1) = (unsigned short)product;
                *(dP + (srcPitch)) = (unsigned short)product1;
                *(dP + 1 + (srcPitch)) = (unsigned short)product2;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////

void SuperEagle_ex6(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    int finWidth = srcPitch >> 1;
    DWORD line;
    unsigned short *dP;
    unsigned short *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;
    DWORD color4, color5, color6;
    DWORD color1, color2, color3;
    DWORD colorA1, colorA2, colorB1, colorB2, colorS1, colorS2;
    DWORD product1a, product1b, product2a, product2b;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (unsigned short *)srcPtr;
            dP = (unsigned short *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0)
                    iYA = 0;
                else
                    iYA = finWidth;
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitch;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorB1 = *(bP - iYA);
                colorB2 = *(bP - iYA + iXB);

                color4 = *(bP - iXA);
                color5 = *(bP);
                color6 = *(bP + iXB);
                colorS2 = *(bP + iXC);

                color1 = *(bP + iYB - iXA);
                color2 = *(bP + iYB);
                color3 = *(bP + iYB + iXB);
                colorS1 = *(bP + iYB + iXC);

                colorA1 = *(bP + iYC);
                colorA2 = *(bP + iYC + iXB);

                if (color2 == color6 && color5 != color3) {
                    product1b = product2a = color2;
                    if ((color1 == color2) || (color6 == colorB2)) {
                        product1a = INTERPOLATE6(color2, color5);
                        product1a = INTERPOLATE6(color2, product1a);
                    } else {
                        product1a = INTERPOLATE6(color5, color6);
                    }

                    if ((color6 == colorS2) || (color2 == colorA1)) {
                        product2b = INTERPOLATE6(color2, color3);
                        product2b = INTERPOLATE6(color2, product2b);
                    } else {
                        product2b = INTERPOLATE6(color2, color3);
                    }
                } else if (color5 == color3 && color2 != color6) {
                    product2b = product1a = color5;

                    if ((colorB1 == color5) || (color3 == colorS1)) {
                        product1b = INTERPOLATE6(color5, color6);
                        product1b = INTERPOLATE6(color5, product1b);
                    } else {
                        product1b = INTERPOLATE6(color5, color6);
                    }

                    if ((color3 == colorA2) || (color4 == color5)) {
                        product2a = INTERPOLATE6(color5, color2);
                        product2a = INTERPOLATE6(color5, product2a);
                    } else {
                        product2a = INTERPOLATE6(color2, color3);
                    }
                } else if (color5 == color3 && color2 == color6) {
                    register int r = 0;

                    r += GET_RESULT((color6), (color5), (color1), (colorA1));
                    r += GET_RESULT((color6), (color5), (color4), (colorB1));
                    r += GET_RESULT((color6), (color5), (colorA2), (colorS1));
                    r += GET_RESULT((color6), (color5), (colorB2), (colorS2));

                    if (r > 0) {
                        product1b = product2a = color2;
                        product1a = product2b = INTERPOLATE6(color5, color6);
                    } else if (r < 0) {
                        product2b = product1a = color5;
                        product1b = product2a = INTERPOLATE6(color5, color6);
                    } else {
                        product2b = product1a = color5;
                        product1b = product2a = color2;
                    }
                } else {
                    product2b = product1a = INTERPOLATE6(color2, color6);
                    product2b = Q_INTERPOLATE6(color3, color3, color3, product2b);
                    product1a = Q_INTERPOLATE6(color5, color5, color5, product1a);

                    product2a = product1b = INTERPOLATE6(color5, color3);
                    product2a = Q_INTERPOLATE6(color2, color2, color2, product2a);
                    product1b = Q_INTERPOLATE6(color6, color6, color6, product1b);
                }

                *dP = (unsigned short)product1a;
                *(dP + 1) = (unsigned short)product1b;
                *(dP + (srcPitch)) = (unsigned short)product2a;
                *(dP + 1 + (srcPitch)) = (unsigned short)product2b;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

void Scale2x_ex6_5(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    int looph, loopw;

    unsigned char *srcpix = srcPtr;
    unsigned char *dstpix = dstBitmap;

    const int srcpitch = srcPitch;
    const int dstpitch = srcPitch << 1;

    unsigned short E0, E1, E2, E3, B, D, E, F, H;
    for (looph = 0; looph < height; ++looph) {
        for (loopw = 0; loopw < width; ++loopw) {
            B = *(unsigned short *)(srcpix + (MAX(0, looph - 1) * srcpitch) + (2 * loopw));
            D = *(unsigned short *)(srcpix + (looph * srcpitch) + (2 * MAX(0, loopw - 1)));
            E = *(unsigned short *)(srcpix + (looph * srcpitch) + (2 * loopw));
            F = *(unsigned short *)(srcpix + (looph * srcpitch) + (2 * MIN(width - 1, loopw + 1)));
            H = *(unsigned short *)(srcpix + (MIN(height - 1, looph + 1) * srcpitch) + (2 * loopw));

            if (B != H && D != F) {
                E0 = D == B ? D : E;
                E1 = B == F ? F : E;
                E2 = D == H ? D : E;
                E3 = H == F ? F : E;
            } else {
                E0 = E;
                E1 = E;
                E2 = E;
                E3 = E;
            }

            *(unsigned short *)(dstpix + looph * 2 * dstpitch + loopw * 2 * 2) = E0;
            *(unsigned short *)(dstpix + looph * 2 * dstpitch + (loopw * 2 + 1) * 2) = E1;
            *(unsigned short *)(dstpix + (looph * 2 + 1) * dstpitch + loopw * 2 * 2) = E2;
            *(unsigned short *)(dstpix + (looph * 2 + 1) * dstpitch + (loopw * 2 + 1) * 2) = E3;
        }
    }
}

////////////////////////////////////////////////////////////////////////
static __inline void scale3x_16_def_whole(unsigned short *dst0, unsigned short *dst1, unsigned short *dst2,
                                          const unsigned short *src0, const unsigned short *src1,
                                          const unsigned short *src2, unsigned count) {
    // assert(count >= 2);

    /* first pixel */
    if (src0[0] != src2[0] && src1[0] != src1[1]) {
        dst0[0] = src1[0];
        dst0[1] = (src1[0] == src0[0] && src1[0] != src0[1]) || (src1[1] == src0[0] && src1[0] != src0[0]) ? src0[0]
                                                                                                           : src1[0];
        dst0[2] = src1[1] == src0[0] ? src1[1] : src1[0];
        dst1[0] = (src1[0] == src0[0] && src1[0] != src2[0]) || (src1[0] == src2[0] && src1[0] != src0[0]) ? src1[0]
                                                                                                           : src1[0];
        dst1[1] = src1[0];
        dst1[2] = (src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1]) ? src1[1]
                                                                                                           : src1[0];
        dst2[0] = src1[0];
        dst2[1] = (src1[0] == src2[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src2[0]) ? src2[0]
                                                                                                           : src1[0];
        dst2[2] = src1[1] == src2[0] ? src1[1] : src1[0];
    } else {
        dst0[0] = src1[0];
        dst0[1] = src1[0];
        dst0[2] = src1[0];
        dst1[0] = src1[0];
        dst1[1] = src1[0];
        dst1[2] = src1[0];
        dst2[0] = src1[0];
        dst2[1] = src1[0];
        dst2[2] = src1[0];
    }
    ++src0;
    ++src1;
    ++src2;
    dst0 += 3;
    dst1 += 3;
    dst2 += 3;

    /* central pixels */
    count -= 2;
    while (count) {
        if (src0[0] != src2[0] && src1[-1] != src1[1]) {
            dst0[0] = src1[-1] == src0[0] ? src1[-1] : src1[0];
            dst0[1] = (src1[-1] == src0[0] && src1[0] != src0[1]) || (src1[1] == src0[0] && src1[0] != src0[-1])
                          ? src0[0]
                          : src1[0];
            dst0[2] = src1[1] == src0[0] ? src1[1] : src1[0];
            dst1[0] = (src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1])
                          ? src1[-1]
                          : src1[0];
            dst1[1] = src1[0];
            dst1[2] = (src1[1] == src0[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src0[1])
                          ? src1[1]
                          : src1[0];
            dst2[0] = src1[-1] == src2[0] ? src1[-1] : src1[0];
            dst2[1] = (src1[-1] == src2[0] && src1[0] != src2[1]) || (src1[1] == src2[0] && src1[0] != src2[-1])
                          ? src2[0]
                          : src1[0];
            dst2[2] = src1[1] == src2[0] ? src1[1] : src1[0];
        } else {
            dst0[0] = src1[0];
            dst0[1] = src1[0];
            dst0[2] = src1[0];
            dst1[0] = src1[0];
            dst1[1] = src1[0];
            dst1[2] = src1[0];
            dst2[0] = src1[0];
            dst2[1] = src1[0];
            dst2[2] = src1[0];
        }

        ++src0;
        ++src1;
        ++src2;
        dst0 += 3;
        dst1 += 3;
        dst2 += 3;
        --count;
    }

    /* last pixel */
    if (src0[0] != src2[0] && src1[-1] != src1[0]) {
        dst0[0] = src1[-1] == src0[0] ? src1[-1] : src1[0];
        dst0[1] = (src1[-1] == src0[0] && src1[0] != src0[0]) || (src1[0] == src0[0] && src1[0] != src0[-1]) ? src0[0]
                                                                                                             : src1[0];
        dst0[2] = src1[0];
        dst1[0] = (src1[-1] == src0[0] && src1[0] != src2[-1]) || (src1[-1] == src2[0] && src1[0] != src0[-1])
                      ? src1[-1]
                      : src1[0];
        dst1[1] = src1[0];
        dst1[2] = (src1[0] == src0[0] && src1[0] != src2[0]) || (src1[0] == src2[0] && src1[0] != src0[0]) ? src1[0]
                                                                                                           : src1[0];
        dst2[0] = src1[-1] == src2[0] ? src1[-1] : src1[0];
        dst2[1] = (src1[-1] == src2[0] && src1[0] != src2[0]) || (src1[0] == src2[0] && src1[0] != src2[-1]) ? src2[0]
                                                                                                             : src1[0];
        dst2[2] = src1[0];
    } else {
        dst0[0] = src1[0];
        dst0[1] = src1[0];
        dst0[2] = src1[0];
        dst1[0] = src1[0];
        dst1[1] = src1[0];
        dst1[2] = src1[0];
        dst2[0] = src1[0];
        dst2[1] = src1[0];
        dst2[2] = src1[0];
    }
}

void Scale3x_ex6_5(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height) {
    int count = height;
    int dstPitch = srcPitch;

    unsigned short *dst0 = (unsigned short *)dstPtr;
    unsigned short *dst1 = dst0 + dstPitch;
    unsigned short *dst2 = dst1 + dstPitch;

    unsigned short *src0 = (unsigned short *)srcPtr;
    unsigned short *src1 = src0 + (srcPitch >> 1);
    unsigned short *src2 = src1 + (srcPitch >> 1);
    scale3x_16_def_whole(dst0, dst1, dst2, src0, src1, src2, count);

    count -= 2;
    while (count) {
        dst0 += dstPitch * 3;
        dst1 += dstPitch * 3;
        dst2 += dstPitch * 3;

        scale3x_16_def_whole(dst0, dst1, dst2, src0, src1, src2, width);
        src0 = src1;
        src1 = src2;
        src2 += srcPitch >> 1;
        --count;
    }
    dst0 += dstPitch * 3;
    dst1 += dstPitch * 3;
    dst2 += dstPitch * 3;

    scale3x_16_def_whole(dst0, dst1, dst2, src0, src1, src1, width);
}

////////////////////////////////////////////////////////////////////////

/*
#define colorMask5     0x0000F7DE
#define lowPixelMask5  0x00000821
#define qcolorMask5    0x0000E79c
#define qlowpixelMask5 0x00001863
*/

#define colorMask5 0x00007BDE
#define lowPixelMask5 0x00000421
#define qcolorMask5 0x0000739c
#define qlowpixelMask5 0x00000C63

#define INTERPOLATE5(A, B) ((((A & colorMask5) >> 1) + ((B & colorMask5) >> 1) + (A & B & lowPixelMask5)))
#define Q_INTERPOLATE5(A, B, C, D)                                                                                 \
    (((((A & qcolorMask5) >> 2) + ((B & qcolorMask5) >> 2) + ((C & qcolorMask5) >> 2) + ((D & qcolorMask5) >> 2) + \
       ((((A & qlowpixelMask5) + (B & qlowpixelMask5) + (C & qlowpixelMask5) + (D & qlowpixelMask5)) >> 2) &       \
        qlowpixelMask5))))

void Super2xSaI_ex5(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    int finWidth = srcPitch >> 1;
    DWORD line;
    unsigned short *dP;
    unsigned short *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;
    DWORD color4, color5, color6;
    DWORD color1, color2, color3;
    DWORD colorA0, colorA1, colorA2, colorA3, colorB0, colorB1, colorB2, colorB3, colorS1, colorS2;
    DWORD product1a, product1b, product2a, product2b;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (unsigned short *)srcPtr;
            dP = (unsigned short *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                //---------------------------------------    B1 B2
                //                                         4  5  6 S2
                //                                         1  2  3 S1
                //                                           A1 A2
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0)
                    iYA = 0;
                else
                    iYA = finWidth;
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitch;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorB0 = *(bP - iYA - iXA);
                colorB1 = *(bP - iYA);
                colorB2 = *(bP - iYA + iXB);
                colorB3 = *(bP - iYA + iXC);

                color4 = *(bP - iXA);
                color5 = *(bP);
                color6 = *(bP + iXB);
                colorS2 = *(bP + iXC);

                color1 = *(bP + iYB - iXA);
                color2 = *(bP + iYB);
                color3 = *(bP + iYB + iXB);
                colorS1 = *(bP + iYB + iXC);

                colorA0 = *(bP + iYC - iXA);
                colorA1 = *(bP + iYC);
                colorA2 = *(bP + iYC + iXB);
                colorA3 = *(bP + iYC + iXC);

                //--------------------------------------
                if (color2 == color6 && color5 != color3) {
                    product2b = product1b = color2;
                } else if (color5 == color3 && color2 != color6) {
                    product2b = product1b = color5;
                } else if (color5 == color3 && color2 == color6) {
                    register int r = 0;

                    r += GET_RESULT((color6), (color5), (color1), (colorA1));
                    r += GET_RESULT((color6), (color5), (color4), (colorB1));
                    r += GET_RESULT((color6), (color5), (colorA2), (colorS1));
                    r += GET_RESULT((color6), (color5), (colorB2), (colorS2));

                    if (r > 0)
                        product2b = product1b = color6;
                    else if (r < 0)
                        product2b = product1b = color5;
                    else {
                        product2b = product1b = INTERPOLATE5(color5, color6);
                    }
                } else {
                    if (color6 == color3 && color3 == colorA1 && color2 != colorA2 && color3 != colorA0)
                        product2b = Q_INTERPOLATE5(color3, color3, color3, color2);
                    else if (color5 == color2 && color2 == colorA2 && colorA1 != color3 && color2 != colorA3)
                        product2b = Q_INTERPOLATE5(color2, color2, color2, color3);
                    else
                        product2b = INTERPOLATE5(color2, color3);

                    if (color6 == color3 && color6 == colorB1 && color5 != colorB2 && color6 != colorB0)
                        product1b = Q_INTERPOLATE5(color6, color6, color6, color5);
                    else if (color5 == color2 && color5 == colorB2 && colorB1 != color6 && color5 != colorB3)
                        product1b = Q_INTERPOLATE5(color6, color5, color5, color5);
                    else
                        product1b = INTERPOLATE5(color5, color6);
                }

                if (color5 == color3 && color2 != color6 && color4 == color5 && color5 != colorA2)
                    product2a = INTERPOLATE5(color2, color5);
                else if (color5 == color1 && color6 == color5 && color4 != color2 && color5 != colorA0)
                    product2a = INTERPOLATE5(color2, color5);
                else
                    product2a = color2;

                if (color2 == color6 && color5 != color3 && color1 == color2 && color2 != colorB2)
                    product1a = INTERPOLATE5(color2, color5);
                else if (color4 == color2 && color3 == color2 && color1 != color5 && color2 != colorB0)
                    product1a = INTERPOLATE5(color2, color5);
                else
                    product1a = color5;

                *dP = (unsigned short)product1a;
                *(dP + 1) = (unsigned short)product1b;
                *(dP + (srcPitch)) = (unsigned short)product2a;
                *(dP + 1 + (srcPitch)) = (unsigned short)product2b;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////

void Std2xSaI_ex5(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    int finWidth = srcPitch >> 1;
    DWORD line;
    unsigned short *dP;
    unsigned short *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;
    DWORD colorA, colorB;
    DWORD colorC, colorD, colorE, colorF, colorG, colorH, colorI, colorJ, colorK, colorL, colorM, colorN, colorO,
        colorP;
    DWORD product, product1, product2;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (unsigned short *)srcPtr;
            dP = (unsigned short *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                //---------------------------------------
                // Map of the pixels:                    I|E F|J
                //                                       G|A B|K
                //                                       H|C D|L
                //                                       M|N O|P
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0)
                    iYA = 0;
                else
                    iYA = finWidth;
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitch;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorI = *(bP - iYA - iXA);
                colorE = *(bP - iYA);
                colorF = *(bP - iYA + iXB);
                colorJ = *(bP - iYA + iXC);

                colorG = *(bP - iXA);
                colorA = *(bP);
                colorB = *(bP + iXB);
                colorK = *(bP + iXC);

                colorH = *(bP + iYB - iXA);
                colorC = *(bP + iYB);
                colorD = *(bP + iYB + iXB);
                colorL = *(bP + iYB + iXC);

                colorM = *(bP + iYC - iXA);
                colorN = *(bP + iYC);
                colorO = *(bP + iYC + iXB);
                colorP = *(bP + iYC + iXC);

                if ((colorA == colorD) && (colorB != colorC)) {
                    if (((colorA == colorE) && (colorB == colorL)) ||
                        ((colorA == colorC) && (colorA == colorF) && (colorB != colorE) && (colorB == colorJ))) {
                        product = colorA;
                    } else {
                        product = INTERPOLATE5(colorA, colorB);
                    }

                    if (((colorA == colorG) && (colorC == colorO)) ||
                        ((colorA == colorB) && (colorA == colorH) && (colorG != colorC) && (colorC == colorM))) {
                        product1 = colorA;
                    } else {
                        product1 = INTERPOLATE5(colorA, colorC);
                    }
                    product2 = colorA;
                } else if ((colorB == colorC) && (colorA != colorD)) {
                    if (((colorB == colorF) && (colorA == colorH)) ||
                        ((colorB == colorE) && (colorB == colorD) && (colorA != colorF) && (colorA == colorI))) {
                        product = colorB;
                    } else {
                        product = INTERPOLATE5(colorA, colorB);
                    }

                    if (((colorC == colorH) && (colorA == colorF)) ||
                        ((colorC == colorG) && (colorC == colorD) && (colorA != colorH) && (colorA == colorI))) {
                        product1 = colorC;
                    } else {
                        product1 = INTERPOLATE5(colorA, colorC);
                    }
                    product2 = colorB;
                } else if ((colorA == colorD) && (colorB == colorC)) {
                    if (colorA == colorB) {
                        product = colorA;
                        product1 = colorA;
                        product2 = colorA;
                    } else {
                        register int r = 0;
                        product1 = INTERPOLATE5(colorA, colorC);
                        product = INTERPOLATE5(colorA, colorB);

                        r += GetResult1(colorA, colorB, colorG, colorE, colorI);
                        r += GetResult2(colorB, colorA, colorK, colorF, colorJ);
                        r += GetResult2(colorB, colorA, colorH, colorN, colorM);
                        r += GetResult1(colorA, colorB, colorL, colorO, colorP);

                        if (r > 0)
                            product2 = colorA;
                        else if (r < 0)
                            product2 = colorB;
                        else {
                            product2 = Q_INTERPOLATE5(colorA, colorB, colorC, colorD);
                        }
                    }
                } else {
                    product2 = Q_INTERPOLATE5(colorA, colorB, colorC, colorD);

                    if ((colorA == colorC) && (colorA == colorF) && (colorB != colorE) && (colorB == colorJ)) {
                        product = colorA;
                    } else if ((colorB == colorE) && (colorB == colorD) && (colorA != colorF) && (colorA == colorI)) {
                        product = colorB;
                    } else {
                        product = INTERPOLATE5(colorA, colorB);
                    }

                    if ((colorA == colorB) && (colorA == colorH) && (colorG != colorC) && (colorC == colorM)) {
                        product1 = colorA;
                    } else if ((colorC == colorG) && (colorC == colorD) && (colorA != colorH) && (colorA == colorI)) {
                        product1 = colorC;
                    } else {
                        product1 = INTERPOLATE5(colorA, colorC);
                    }
                }

                *dP = (unsigned short)colorA;
                *(dP + 1) = (unsigned short)product;
                *(dP + (srcPitch)) = (unsigned short)product1;
                *(dP + 1 + (srcPitch)) = (unsigned short)product2;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////

void SuperEagle_ex5(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstBitmap, int width, int height) {
    DWORD dstPitch = srcPitch << 1;
    int finWidth = srcPitch >> 1;
    DWORD line;
    unsigned short *dP;
    unsigned short *bP;
    int iXA, iXB, iXC, iYA, iYB, iYC, finish;
    DWORD color4, color5, color6;
    DWORD color1, color2, color3;
    DWORD colorA1, colorA2, colorB1, colorB2, colorS1, colorS2;
    DWORD product1a, product1b, product2a, product2b;

    line = 0;

    {
        for (; height; height -= 1) {
            bP = (unsigned short *)srcPtr;
            dP = (unsigned short *)(dstBitmap + line * dstPitch);
            for (finish = width; finish; finish -= 1) {
                if (finish == finWidth)
                    iXA = 0;
                else
                    iXA = 1;
                if (finish > 4) {
                    iXB = 1;
                    iXC = 2;
                } else if (finish > 3) {
                    iXB = 1;
                    iXC = 1;
                } else {
                    iXB = 0;
                    iXC = 0;
                }
                if (line == 0)
                    iYA = 0;
                else
                    iYA = finWidth;
                if (height > 4) {
                    iYB = finWidth;
                    iYC = srcPitch;
                } else if (height > 3) {
                    iYB = finWidth;
                    iYC = finWidth;
                } else {
                    iYB = 0;
                    iYC = 0;
                }

                colorB1 = *(bP - iYA);
                colorB2 = *(bP - iYA + iXB);

                color4 = *(bP - iXA);
                color5 = *(bP);
                color6 = *(bP + iXB);
                colorS2 = *(bP + iXC);

                color1 = *(bP + iYB - iXA);
                color2 = *(bP + iYB);
                color3 = *(bP + iYB + iXB);
                colorS1 = *(bP + iYB + iXC);

                colorA1 = *(bP + iYC);
                colorA2 = *(bP + iYC + iXB);

                if (color2 == color6 && color5 != color3) {
                    product1b = product2a = color2;
                    if ((color1 == color2) || (color6 == colorB2)) {
                        product1a = INTERPOLATE5(color2, color5);
                        product1a = INTERPOLATE5(color2, product1a);
                    } else {
                        product1a = INTERPOLATE5(color5, color6);
                    }

                    if ((color6 == colorS2) || (color2 == colorA1)) {
                        product2b = INTERPOLATE5(color2, color3);
                        product2b = INTERPOLATE5(color2, product2b);
                    } else {
                        product2b = INTERPOLATE5(color2, color3);
                    }
                } else if (color5 == color3 && color2 != color6) {
                    product2b = product1a = color5;

                    if ((colorB1 == color5) || (color3 == colorS1)) {
                        product1b = INTERPOLATE5(color5, color6);
                        product1b = INTERPOLATE5(color5, product1b);
                    } else {
                        product1b = INTERPOLATE5(color5, color6);
                    }

                    if ((color3 == colorA2) || (color4 == color5)) {
                        product2a = INTERPOLATE5(color5, color2);
                        product2a = INTERPOLATE5(color5, product2a);
                    } else {
                        product2a = INTERPOLATE5(color2, color3);
                    }
                } else if (color5 == color3 && color2 == color6) {
                    register int r = 0;

                    r += GET_RESULT((color6), (color5), (color1), (colorA1));
                    r += GET_RESULT((color6), (color5), (color4), (colorB1));
                    r += GET_RESULT((color6), (color5), (colorA2), (colorS1));
                    r += GET_RESULT((color6), (color5), (colorB2), (colorS2));

                    if (r > 0) {
                        product1b = product2a = color2;
                        product1a = product2b = INTERPOLATE5(color5, color6);
                    } else if (r < 0) {
                        product2b = product1a = color5;
                        product1b = product2a = INTERPOLATE5(color5, color6);
                    } else {
                        product2b = product1a = color5;
                        product1b = product2a = color2;
                    }
                } else {
                    product2b = product1a = INTERPOLATE5(color2, color6);
                    product2b = Q_INTERPOLATE5(color3, color3, color3, product2b);
                    product1a = Q_INTERPOLATE5(color5, color5, color5, product1a);

                    product2a = product1b = INTERPOLATE5(color5, color3);
                    product2a = Q_INTERPOLATE5(color2, color2, color2, product2a);
                    product1b = Q_INTERPOLATE5(color6, color6, color6, product1b);
                }

                *dP = (unsigned short)product1a;
                *(dP + 1) = (unsigned short)product1b;
                *(dP + (srcPitch)) = (unsigned short)product2a;
                *(dP + 1 + (srcPitch)) = (unsigned short)product2b;

                bP += 1;
                dP += 2;
            }  // end of for ( finish= width etc..)

            line += 2;
            srcPtr += srcPitch;
        };  // endof: for (; height; height--)
    }
}

////////////////////////////////////////////////////////////////////////
// own swap buffer func (window/fullscreen)
////////////////////////////////////////////////////////////////////////

sDX DX;
static DDSURFACEDESC ddsd;
GUID guiDev;
BOOL bDeviceOK;
HWND hWGPU;
int iSysMemory = 0;
int iFPSEInterface = 0;
int iRefreshRate;
BOOL bVsync = FALSE;
BOOL bVsync_Key = FALSE;

void (*BlitScreen)(unsigned char *, long, long);
void (*pExtraBltFunc)(void);
void (*p2XSaIFunc)(unsigned char *, DWORD, unsigned char *, int, int);

////////////////////////////////////////////////////////////////////////

static __inline void WaitVBlank(void) {
    if (bVsync_Key) {
        IDirectDraw2_WaitForVerticalBlank(DX.DD, DDWAITVB_BLOCKBEGIN, 0);
    }
}

////////////////////////////////////////////////////////////////////////

void BlitScreen32(unsigned char *surf, long x, long y)  // BLIT IN 32bit COLOR MODE
{
    unsigned char *pD;
    unsigned long lu;
    unsigned short s;
    unsigned int startxy;
    short row, column;
    short dx = (short)PreviousPSXDisplay.Range.x1;
    short dy = (short)PreviousPSXDisplay.DisplayMode.y;

    if (iDebugMode && iFVDisplay) {
        dx = 1024;
        dy = iGPUHeight;
        x = 0;
        y = 0;

        for (column = 0; column < dy; column++) {
            startxy = ((1024) * (column + y)) + x;
            for (row = 0; row < dx; row++) {
                s = psxVuw[startxy++];
                *((unsigned long *)((surf) + (column * ddsd.lPitch) + row * 4)) =
                    ((((s << 19) & 0xf80000) | ((s << 6) & 0xf800) | ((s >> 7) & 0xf8)) & 0xffffff) | 0xff000000;
            }
        }
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * ddsd.lPitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    surf += PreviousPSXDisplay.Range.x0 << 2;

    if (PSXDisplay.RGB24) {
        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((surf) + (column * ddsd.lPitch) + row * 4)) =
                        0xff000000 | (BLUE(lu) << 16) | (GREEN(lu) << 8) | (RED(lu));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((surf) + (column * ddsd.lPitch) + row * 4)) =
                        0xff000000 | (RED(lu) << 16) | (GREEN(lu) << 8) | (BLUE(lu));
                    pD += 3;
                }
            }
        }
    } else {
        for (column = 0; column < dy; column++) {
            startxy = ((1024) * (column + y)) + x;
            for (row = 0; row < dx; row++) {
                s = psxVuw[startxy++];
                *((unsigned long *)((surf) + (column * ddsd.lPitch) + row * 4)) =
                    ((((s << 19) & 0xf80000) | ((s << 6) & 0xf800) | ((s >> 7) & 0xf8)) & 0xffffff) | 0xff000000;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////

void BlitScreen32_2xSaI(unsigned char *surf, long x, long y)  // BLIT IN 32bit COLOR MODE
{
    unsigned char *pD;
    unsigned long lu;
    unsigned short s;
    unsigned int startxy, off1, off2;
    short row, column;
    short dx = (short)PreviousPSXDisplay.Range.x1;
    short dy = (short)PreviousPSXDisplay.DisplayMode.y;
    unsigned char *pS = (unsigned char *)pSaISmallBuff;
    unsigned long *pS1, *pS2;

    if (PreviousPSXDisplay.DisplayMode.x > 512) {
        BlitScreen32(surf, x, y);
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        pS += PreviousPSXDisplay.Range.y0 * 2048;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    pS += PreviousPSXDisplay.Range.x0 << 2;

    if (PSXDisplay.RGB24) {
        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((pS) + (column * 2048) + row * 4)) =
                        0xff000000 | (BLUE(lu) << 16) | (GREEN(lu) << 8) | (RED(lu));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((pS) + (column * 2048) + row * 4)) =
                        0xff000000 | (RED(lu) << 16) | (GREEN(lu) << 8) | (BLUE(lu));
                    pD += 3;
                }
            }
        }
    } else {
        for (column = 0; column < dy; column++) {
            startxy = ((1024) * (column + y)) + x;
            for (row = 0; row < dx; row++) {
                s = psxVuw[startxy++];
                *((unsigned long *)((pS) + (column * 2048) + row * 4)) =
                    ((((s << 19) & 0xf80000) | ((s << 6) & 0xf800) | ((s >> 7) & 0xf8)) & 0xffffff) | 0xff000000;
            }
        }
    }

    // ok, here we have filled pSaISmallBuff with PreviousPSXDisplay.DisplayMode.x * PreviousPSXDisplay.DisplayMode.y
    // (*4) data now do a 2xSai blit to pSaIBigBuff

    p2XSaIFunc((unsigned char *)pSaISmallBuff, 2048, (unsigned char *)pSaIBigBuff, PreviousPSXDisplay.DisplayMode.x,
               PreviousPSXDisplay.DisplayMode.y);

    // ok, here we have pSaIBigBuff filled with the 2xSai image...
    // now transfer it to the surface

    dx = (short)PreviousPSXDisplay.DisplayMode.x << 1;
    dy = (short)PreviousPSXDisplay.DisplayMode.y << 1;
    off1 = (ddsd.lPitch >> 2) - dx;
    off2 = 1024 - dx;

    pS1 = (unsigned long *)surf;
    pS2 = (unsigned long *)pSaIBigBuff;

    for (column = 0; column < dy; column++) {
        for (row = 0; row < dx; row++) {
            *(pS1++) = *(pS2++);
        }
        pS1 += off1;
        pS2 += off2;
    }
}

////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////
void BlitScreen32_3xSaI(unsigned char *surf, long x, long y)  // BLIT IN 32bit COLOR MODE
{
    unsigned char *pD;
    unsigned long lu;
    unsigned short s;
    unsigned int startxy, off1, off2;
    short row, column;
    short dx = (short)PreviousPSXDisplay.Range.x1;
    short dy = (short)PreviousPSXDisplay.DisplayMode.y;
    unsigned char *pS = (unsigned char *)pSaISmallBuff;
    unsigned long *pS1, *pS2;

    if (PreviousPSXDisplay.DisplayMode.x > 512) {
        BlitScreen32(surf, x, y);
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        pS += PreviousPSXDisplay.Range.y0 * 2048;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    pS += PreviousPSXDisplay.Range.x0 << 2;

    if (PSXDisplay.RGB24) {
        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((pS) + (column * 2048) + row * 4)) =
                        0xff000000 | (BLUE(lu) << 16) | (GREEN(lu) << 8) | (RED(lu));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;
                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned long *)((pS) + (column * 2048) + row * 4)) =
                        0xff000000 | (RED(lu) << 16) | (GREEN(lu) << 8) | (BLUE(lu));
                    pD += 3;
                }
            }
        }
    } else {
        for (column = 0; column < dy; column++) {
            startxy = ((1024) * (column + y)) + x;
            for (row = 0; row < dx; row++) {
                s = psxVuw[startxy++];
                *((unsigned long *)((pS) + (column * 2048) + row * 4)) =
                    ((((s << 19) & 0xf80000) | ((s << 6) & 0xf800) | ((s >> 7) & 0xf8)) & 0xffffff) | 0xff000000;
            }
        }
    }

    // ok, here we have filled pSaISmallBuff with PreviousPSXDisplay.DisplayMode.x * PreviousPSXDisplay.DisplayMode.y
    // (*4) data now do a 2xSai blit to pSaIBigBuff

    p2XSaIFunc((unsigned char *)pSaISmallBuff, 2048, (unsigned char *)pSaIBigBuff, PreviousPSXDisplay.DisplayMode.x,
               PreviousPSXDisplay.DisplayMode.y);

    // ok, here we have pSaIBigBuff filled with the 2xSai image...
    // now transfer it to the surface
    // CHANGED << 1 to * 3

    dx = (short)PreviousPSXDisplay.DisplayMode.x * 3;
    dy = (short)PreviousPSXDisplay.DisplayMode.y * 3;

    off1 = (ddsd.lPitch >> 2) - dx;
    off2 = 1024 - dx;

    pS1 = (unsigned long *)surf;
    pS2 = (unsigned long *)pSaIBigBuff;

    for (column = 0; column < dy; column++) {
        for (row = 0; row < dx; row++) {
            *(pS1++) = *(pS2++);
        }
        pS1 += off1;
        pS2 += off2;
    }
}
//////////////////////////////////////////////////////////////////////
void BlitScreen16(unsigned char *surf, long x, long y)  // BLIT IN 16bit COLOR MODE
{
    unsigned long lu;
    unsigned short row, column;
    unsigned short dx = (unsigned short)PreviousPSXDisplay.Range.x1;
    unsigned short dy = (unsigned short)PreviousPSXDisplay.DisplayMode.y;

    if (iDebugMode && iFVDisplay) {
        unsigned short LineOffset, SurfOffset;
        unsigned long *SRCPtr;
        unsigned long *DSTPtr;

        dx = 1024;
        dy = iGPUHeight;
        x = 0;
        y = 0;

        SRCPtr = (unsigned long *)(psxVuw);
        DSTPtr = ((unsigned long *)surf);

        dx >>= 1;

        LineOffset = 512 - dx;
        SurfOffset = (ddsd.lPitch >> 2) - dx;

        for (column = 0; column < dy; column++) {
            for (row = 0; row < dx; row++) {
                lu = *SRCPtr++;

                *DSTPtr++ = ((lu << 11) & 0xf800f800) | ((lu << 1) & 0x7c007c0) | ((lu >> 10) & 0x1f001f);
            }
            SRCPtr += LineOffset;
            DSTPtr += SurfOffset;
        }
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * ddsd.lPitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    if (PSXDisplay.RGB24) {
        unsigned char *pD;
        unsigned int startxy;

        surf += PreviousPSXDisplay.Range.x0 << 1;

        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((surf) + (column * ddsd.lPitch) + (row << 1))) =
                        (unsigned short)(((BLUE(lu) << 8) & 0xf800) | ((GREEN(lu) << 3) & 0x7e0) | (RED(lu) >> 3));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((surf) + (column * ddsd.lPitch) + (row << 1))) =
                        (unsigned short)(((RED(lu) << 8) & 0xf800) | ((GREEN(lu) << 3) & 0x7e0) | (BLUE(lu) >> 3));
                    pD += 3;
                }
            }
        }
    } else {
        unsigned short LineOffset, SurfOffset;
        unsigned long *SRCPtr = (unsigned long *)(psxVuw + (y << 10) + x);
        unsigned long *DSTPtr = ((unsigned long *)surf) + (PreviousPSXDisplay.Range.x0 >> 1);

        dx >>= 1;

        LineOffset = 512 - dx;
        SurfOffset = (ddsd.lPitch >> 2) - dx;

        for (column = 0; column < dy; column++) {
            for (row = 0; row < dx; row++) {
                lu = *SRCPtr++;

                *DSTPtr++ = ((lu << 11) & 0xf800f800) | ((lu << 1) & 0x7c007c0) | ((lu >> 10) & 0x1f001f);
            }
            SRCPtr += LineOffset;
            DSTPtr += SurfOffset;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void BlitScreen16_2xSaI(unsigned char *surf, long x, long y)  // BLIT IN 16bit COLOR MODE
{
    unsigned long lu;
    unsigned short row, column, off1, off2;
    unsigned short dx = (unsigned short)PreviousPSXDisplay.Range.x1;
    unsigned short dy = (unsigned short)PreviousPSXDisplay.DisplayMode.y;
    unsigned char *pS = (unsigned char *)pSaISmallBuff;
    unsigned long *pS1, *pS2;

    if (PreviousPSXDisplay.DisplayMode.x > 512) {
        BlitScreen16(surf, x, y);
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        pS += PreviousPSXDisplay.Range.y0 * 1024;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    if (PSXDisplay.RGB24) {
        unsigned char *pD;
        unsigned int startxy;

        pS += PreviousPSXDisplay.Range.x0 << 1;

        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((pS) + (column * 1024) + (row << 1))) =
                        (unsigned short)(((BLUE(lu) << 8) & 0xf800) | ((GREEN(lu) << 3) & 0x7e0) | (RED(lu) >> 3));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((pS) + (column * 1024) + (row << 1))) =
                        (unsigned short)(((RED(lu) << 8) & 0xf800) | ((GREEN(lu) << 3) & 0x7e0) | (BLUE(lu) >> 3));
                    pD += 3;
                }
            }
        }
    } else {
        unsigned short LineOffset, SurfOffset;
        unsigned long *SRCPtr = (unsigned long *)(psxVuw + (y << 10) + x);
        unsigned long *DSTPtr = ((unsigned long *)pS) + (PreviousPSXDisplay.Range.x0 >> 1);

        dx >>= 1;

        LineOffset = 512 - dx;
        SurfOffset = 256 - dx;

        for (column = 0; column < dy; column++) {
            for (row = 0; row < dx; row++) {
                lu = *SRCPtr++;

                *DSTPtr++ = ((lu << 11) & 0xf800f800) | ((lu << 1) & 0x7c007c0) | ((lu >> 10) & 0x1f001f);
            }
            SRCPtr += LineOffset;
            DSTPtr += SurfOffset;
        }
    }

    // ok, here we have filled pSaISmallBuff with PreviousPSXDisplay.DisplayMode.x * PreviousPSXDisplay.DisplayMode.y
    // (*4) data now do a 2xSai blit to pSaIBigBuff

    p2XSaIFunc((unsigned char *)pSaISmallBuff, 1024, (unsigned char *)pSaIBigBuff, PreviousPSXDisplay.DisplayMode.x,
               PreviousPSXDisplay.DisplayMode.y);

    // ok, here we have pSaIBigBuff filled with the 2xSai image...
    // now transfer it to the surface

    dx = (short)PreviousPSXDisplay.DisplayMode.x;
    dy = (short)PreviousPSXDisplay.DisplayMode.y << 1;
    off1 = (ddsd.lPitch >> 2) - dx;
    off2 = 512 - dx;

    pS1 = (unsigned long *)surf;
    pS2 = (unsigned long *)pSaIBigBuff;

    for (column = 0; column < dy; column++) {
        for (row = 0; row < dx; row++) {
            *(pS1++) = *(pS2++);
        }
        pS1 += off1;
        pS2 += off2;
    }
}

void BlitScreen16_3xSaI(unsigned char *surf, long x, long y)  // BLIT IN 16bit COLOR MODE
{
    unsigned long lu;
    unsigned short row, column, off1, off2;
    unsigned short dx = (unsigned short)PreviousPSXDisplay.Range.x1;
    unsigned short dy = (unsigned short)PreviousPSXDisplay.DisplayMode.y;
    unsigned char *pS = (unsigned char *)pSaISmallBuff;
    unsigned long *pS1, *pS2;

    if (PreviousPSXDisplay.DisplayMode.x > 512) {
        BlitScreen16(surf, x, y);
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        pS += PreviousPSXDisplay.Range.y0 * 1024;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    if (PSXDisplay.RGB24) {
        unsigned char *pD;
        unsigned int startxy;

        pS += PreviousPSXDisplay.Range.x0 << 1;

        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((pS) + (column * 1024) + (row << 1))) =
                        (unsigned short)(((BLUE(lu) << 8) & 0xf800) | ((GREEN(lu) << 3) & 0x7e0) | (RED(lu) >> 3));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((pS) + (column * 1024) + (row << 1))) =
                        (unsigned short)(((RED(lu) << 8) & 0xf800) | ((GREEN(lu) << 3) & 0x7e0) | (BLUE(lu) >> 3));
                    pD += 3;
                }
            }
        }
    } else {
        unsigned short LineOffset, SurfOffset;
        unsigned long *SRCPtr = (unsigned long *)(psxVuw + (y << 10) + x);
        unsigned long *DSTPtr = ((unsigned long *)pS) + (PreviousPSXDisplay.Range.x0 >> 1);

        dx >>= 1;

        LineOffset = 512 - dx;
        SurfOffset = 256 - dx;

        for (column = 0; column < dy; column++) {
            for (row = 0; row < dx; row++) {
                lu = *SRCPtr++;

                *DSTPtr++ = ((lu << 11) & 0xf800f800) | ((lu << 1) & 0x7c007c0) | ((lu >> 10) & 0x1f001f);
            }
            SRCPtr += LineOffset;
            DSTPtr += SurfOffset;
        }
    }

    // ok, here we have filled pSaISmallBuff with PreviousPSXDisplay.DisplayMode.x * PreviousPSXDisplay.DisplayMode.y
    // (*4) data now do a 2xSai blit to pSaIBigBuff

    p2XSaIFunc((unsigned char *)pSaISmallBuff, 1024, (unsigned char *)pSaIBigBuff, PreviousPSXDisplay.DisplayMode.x,
               PreviousPSXDisplay.DisplayMode.y);

    // ok, here we have pSaIBigBuff filled with the 2xSai image...
    // now transfer it to the surface

    dx = (short)(PreviousPSXDisplay.DisplayMode.x * 1.5);
    dy = (short)PreviousPSXDisplay.DisplayMode.y * 3;
    off1 = (ddsd.lPitch >> 2) - dx;
    off2 = 512 - dx;

    pS1 = (unsigned long *)surf;
    pS2 = (unsigned long *)pSaIBigBuff;

    for (column = 0; column < dy; column++) {
        for (row = 0; row < dx; row++) {
            *(pS1++) = *(pS2++);
        }
        pS1 += off1;
        pS2 += off2;
    }
}

////////////////////////////////////////////////////////////////////////

void BlitScreen15(unsigned char *surf, long x, long y)  // BLIT IN 16bit COLOR MODE
{
    unsigned long lu;
    unsigned short row, column;
    unsigned short dx = (unsigned short)PreviousPSXDisplay.Range.x1;
    unsigned short dy = (unsigned short)PreviousPSXDisplay.DisplayMode.y;

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * ddsd.lPitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    if (PSXDisplay.RGB24) {
        unsigned char *pD;
        unsigned int startxy;

        surf += PreviousPSXDisplay.Range.x0 << 1;

        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((surf) + (column * ddsd.lPitch) + (row << 1))) =
                        (unsigned short)(((BLUE(lu) << 7) & 0x7c00) | ((GREEN(lu) << 2) & 0x3e0) | (RED(lu) >> 3));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((surf) + (column * ddsd.lPitch) + (row << 1))) =
                        (unsigned short)(((RED(lu) << 7) & 0x7c00) | ((GREEN(lu) << 2) & 0x3e0) | (BLUE(lu) >> 3));
                    pD += 3;
                }
            }
        }
    } else {
        unsigned short LineOffset, SurfOffset;
        unsigned long *SRCPtr = (unsigned long *)(psxVuw + (y << 10) + x);

        unsigned long *DSTPtr = ((unsigned long *)surf) + (PreviousPSXDisplay.Range.x0 >> 1);

        dx >>= 1;

        LineOffset = 512 - dx;
        SurfOffset = (ddsd.lPitch >> 2) - dx;

        for (column = 0; column < dy; column++) {
            for (row = 0; row < dx; row++) {
                lu = *SRCPtr++;

                *DSTPtr++ = ((lu << 10) & 0x7c007c00) | ((lu)&0x3e003e0) | ((lu >> 10) & 0x1f001f);
            }
            SRCPtr += LineOffset;
            DSTPtr += SurfOffset;
        }
    }
}

////////////////////////////////////////////////////////////////////////

void BlitScreen15_2xSaI(unsigned char *surf, long x, long y)  // BLIT IN 16bit COLOR MODE
{
    unsigned long lu;
    unsigned short row, column, off1, off2;
    unsigned short dx = (unsigned short)PreviousPSXDisplay.Range.x1;
    unsigned short dy = (unsigned short)PreviousPSXDisplay.DisplayMode.y;
    unsigned char *pS = (unsigned char *)pSaISmallBuff;
    unsigned long *pS1, *pS2;

    if (PreviousPSXDisplay.DisplayMode.x > 512) {
        BlitScreen15(surf, x, y);
        return;
    }

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        pS += PreviousPSXDisplay.Range.y0 * 1024;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    if (PSXDisplay.RGB24) {
        unsigned char *pD;
        unsigned int startxy;

        pS += PreviousPSXDisplay.Range.x0 << 1;

        if (iFPSEInterface) {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((pS) + (column * 1024) + (row << 1))) =
                        (unsigned short)(((BLUE(lu) << 7) & 0x7c00) | ((GREEN(lu) << 2) & 0x3e0) | (RED(lu) >> 3));
                    pD += 3;
                }
            }
        } else {
            for (column = 0; column < dy; column++) {
                startxy = ((1024) * (column + y)) + x;

                pD = (unsigned char *)&psxVuw[startxy];

                for (row = 0; row < dx; row++) {
                    lu = *((unsigned long *)pD);
                    *((unsigned short *)((pS) + (column * 1024) + (row << 1))) =
                        (unsigned short)(((RED(lu) << 7) & 0x7c00) | ((GREEN(lu) << 2) & 0x3e0) | (BLUE(lu) >> 3));
                    pD += 3;
                }
            }
        }
    } else {
        unsigned short LineOffset, SurfOffset;
        unsigned long *SRCPtr = (unsigned long *)(psxVuw + (y << 10) + x);
        unsigned long *DSTPtr = ((unsigned long *)pS) + (PreviousPSXDisplay.Range.x0 >> 1);

        dx >>= 1;

        LineOffset = 512 - dx;
        SurfOffset = 256 - dx;

        for (column = 0; column < dy; column++) {
            for (row = 0; row < dx; row++) {
                lu = *SRCPtr++;

                *DSTPtr++ = ((lu << 10) & 0x7c007c00) | ((lu)&0x3e003e0) | ((lu >> 10) & 0x1f001f);
            }
            SRCPtr += LineOffset;
            DSTPtr += SurfOffset;
        }
    }

    // ok, here we have filled pSaISmallBuff with PreviousPSXDisplay.DisplayMode.x * PreviousPSXDisplay.DisplayMode.y
    // (*4) data now do a 2xSai blit to pSaIBigBuff

    p2XSaIFunc((unsigned char *)pSaISmallBuff, 1024, (unsigned char *)pSaIBigBuff, PreviousPSXDisplay.DisplayMode.x,
               PreviousPSXDisplay.DisplayMode.y);

    // ok, here we have pSaIBigBuff filled with the 2xSai image...
    // now transfer it to the surface

    dx = (short)PreviousPSXDisplay.DisplayMode.x;
    dy = (short)PreviousPSXDisplay.DisplayMode.y << 1;
    off1 = (ddsd.lPitch >> 2) - dx;
    off2 = 512 - dx;

    pS1 = (unsigned long *)surf;
    pS2 = (unsigned long *)pSaIBigBuff;

    for (column = 0; column < dy; column++) {
        for (row = 0; row < dx; row++) {
            *(pS1++) = *(pS2++);
        }
        pS1 += off1;
        pS2 += off2;
    }
}

////////////////////////////////////////////////////////////////////////

void DoClearScreenBuffer(void)  // CLEAR DX BUFFER
{
    DDBLTFX ddbltfx;

    ddbltfx.dwSize = sizeof(ddbltfx);
    ddbltfx.dwFillColor = 0x00000000;

    IDirectDrawSurface_Blt(DX.DDSRender, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);

    if (iUseNoStretchBlt >= 3) {
        if (pSaISmallBuff) memset(pSaISmallBuff, 0, 512 * 512 * 4);
    }
}

////////////////////////////////////////////////////////////////////////

void DoClearFrontBuffer(void)  // CLEAR PRIMARY BUFFER
{
    DDBLTFX ddbltfx;

    ddbltfx.dwSize = sizeof(ddbltfx);
    ddbltfx.dwFillColor = 0x00000000;

    IDirectDrawSurface_Blt(DX.DDSPrimary, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);
}

////////////////////////////////////////////////////////////////////////

void NoStretchedBlit(void) {
    static int iOldDX = 0;
    static int iOldDY = 0;

    int iDX, iDY;
    int iX = iResX - PreviousPSXDisplay.DisplayMode.x;
    int iY = iResY - PreviousPSXDisplay.DisplayMode.y;

    /*
    float fXS,fYS,fS;
    fXS=(float)iResX/(float)PreviousPSXDisplay.DisplayMode.x;
    fYS=(float)iResY/(float)PreviousPSXDisplay.DisplayMode.y;
    if(fXS<fYS) fS=fXS; else fS=fYS;
    */

    if (iX < 0) {
        iX = 0;
        iDX = iResX;
    } else {
        iX = iX / 2;
        iDX = PreviousPSXDisplay.DisplayMode.x;
    }

    if (iY < 0) {
        iY = 0;
        iDY = iResY;
    } else {
        iY = iY / 2;
        iDY = PreviousPSXDisplay.DisplayMode.y;
    }

    if (iOldDX != iDX || iOldDY != iDY) {
        DDBLTFX ddbltfx;
        ddbltfx.dwSize = sizeof(ddbltfx);
        ddbltfx.dwFillColor = 0x00000000;
        IDirectDrawSurface_Blt(DX.DDSPrimary, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);
        iOldDX = iDX;
        iOldDY = iDY;
    }

    if (iWindowMode) {
        RECT ScreenRect, ViewportRect;
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);
        Point.x += iX;
        Point.y += iY;

        ScreenRect.left = Point.x;
        ScreenRect.top = Point.y;
        ScreenRect.right = iDX + Point.x;
        ScreenRect.bottom = iDY + Point.y;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = iDX;
        ViewportRect.bottom = iDY;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    } else {
        RECT ScreenRect, ViewportRect;

        ScreenRect.left = iX;
        ScreenRect.top = iY;
        ScreenRect.right = iDX + iX;
        ScreenRect.bottom = iDY + iY;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = iDX;
        ViewportRect.bottom = iDY;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    }
    if (DX.DDSScreenPic) DisplayPic();
}

////////////////////////////////////////////////////////////////////////

void NoStretchedBlitEx(void) {
    static int iOldDX = 0;
    static int iOldDY = 0;

    int iDX, iDY, iX, iY;
    float fXS, fYS, fS;

    if (!PreviousPSXDisplay.DisplayMode.x) return;
    if (!PreviousPSXDisplay.DisplayMode.y) return;

    fXS = (float)iResX / (float)PreviousPSXDisplay.DisplayMode.x;
    fYS = (float)iResY / (float)PreviousPSXDisplay.DisplayMode.y;
    if (fXS < fYS)
        fS = fXS;
    else
        fS = fYS;

    iDX = (int)(PreviousPSXDisplay.DisplayMode.x * fS);
    iDY = (int)(PreviousPSXDisplay.DisplayMode.y * fS);

    iX = iResX - iDX;
    iY = iResY - iDY;

    if (iX < 0)
        iX = 0;
    else
        iX = iX / 2;

    if (iY < 0)
        iY = 0;
    else
        iY = iY / 2;

    if (iOldDX != iDX || iOldDY != iDY) {
        DDBLTFX ddbltfx;
        ddbltfx.dwSize = sizeof(ddbltfx);
        ddbltfx.dwFillColor = 0x00000000;
        IDirectDrawSurface_Blt(DX.DDSPrimary, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);
        iOldDX = iDX;
        iOldDY = iDY;
    }

    if (iWindowMode) {
        RECT ScreenRect, ViewportRect;
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);
        Point.x += iX;
        Point.y += iY;

        ScreenRect.left = Point.x;
        ScreenRect.top = Point.y;
        ScreenRect.right = iDX + Point.x;
        ScreenRect.bottom = iDY + Point.y;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = PreviousPSXDisplay.DisplayMode.x;
        ViewportRect.bottom = PreviousPSXDisplay.DisplayMode.y;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    } else {
        RECT ScreenRect, ViewportRect;

        ScreenRect.left = iX;
        ScreenRect.top = iY;
        ScreenRect.right = iDX + iX;
        ScreenRect.bottom = iDY + iY;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = PreviousPSXDisplay.DisplayMode.x;
        ViewportRect.bottom = PreviousPSXDisplay.DisplayMode.y;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    }
    if (DX.DDSScreenPic) DisplayPic();
}

////////////////////////////////////////////////////////////////////////

void StretchedBlit2x(void) {
    if (iWindowMode) {
        RECT ScreenRect, ViewportRect;
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);

        ScreenRect.left = Point.x;
        ScreenRect.top = Point.y;
        ScreenRect.right = iResX + Point.x;
        ScreenRect.bottom = iResY + Point.y;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = PreviousPSXDisplay.DisplayMode.x;
        ViewportRect.bottom = PreviousPSXDisplay.DisplayMode.y;

        if (ViewportRect.right <= 512) {
            ViewportRect.right += ViewportRect.right;
            ViewportRect.bottom += ViewportRect.bottom;
        }

        if (iUseScanLines == 2)  // stupid nvidia scanline mode
        {
            RECT HelperRect = {0, 0, iResX, iResY};

            WaitVBlank();

            IDirectDrawSurface_Blt(DX.DDSHelper, &HelperRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSHelper, &HelperRect, DDBLT_WAIT, NULL);
        } else {
            WaitVBlank();
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
        }
    } else {
        RECT ScreenRect = {0, 0, iResX, iResY},
             ViewportRect = {0, 0, PreviousPSXDisplay.DisplayMode.x, PreviousPSXDisplay.DisplayMode.y};

        if (ViewportRect.right <= 512) {
            ViewportRect.right += ViewportRect.right;
            ViewportRect.bottom += ViewportRect.bottom;
        }

        if (iUseScanLines == 2)  // stupid nvidia scanline mode
        {
            WaitVBlank();

            IDirectDrawSurface_Blt(DX.DDSHelper, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSHelper, &ScreenRect, DDBLT_WAIT, NULL);
        } else {
            WaitVBlank();
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
        }
    }

    if (DX.DDSScreenPic) DisplayPic();
}

////////////////////////////////////////////////////////////////////////

void NoStretchedBlit2x(void) {
    static int iOldDX = 0;
    static int iOldDY = 0;

    int iX, iY, iDX, iDY;
    int iDX2 = PreviousPSXDisplay.DisplayMode.x;
    int iDY2 = PreviousPSXDisplay.DisplayMode.y;
    if (PreviousPSXDisplay.DisplayMode.x <= 512) {
        iDX2 <<= 1;
        iDY2 <<= 1;
    }

    iX = iResX - iDX2;
    iY = iResY - iDY2;

    if (iX < 0) {
        iX = 0;
        iDX = iResX;
    } else {
        iX = iX / 2;
        iDX = iDX2;
    }

    if (iY < 0) {
        iY = 0;
        iDY = iResY;
    } else {
        iY = iY / 2;
        iDY = iDY2;
    }

    if (iOldDX != iDX || iOldDY != iDY) {
        DDBLTFX ddbltfx;
        ddbltfx.dwSize = sizeof(ddbltfx);
        ddbltfx.dwFillColor = 0x00000000;
        IDirectDrawSurface_Blt(DX.DDSPrimary, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);
        iOldDX = iDX;
        iOldDY = iDY;
    }

    if (iWindowMode) {
        RECT ScreenRect, ViewportRect;
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);
        Point.x += iX;
        Point.y += iY;

        ScreenRect.left = Point.x;
        ScreenRect.top = Point.y;
        ScreenRect.right = iDX + Point.x;
        ScreenRect.bottom = iDY + Point.y;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = iDX;
        ViewportRect.bottom = iDY;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    } else {
        RECT ScreenRect, ViewportRect;

        ScreenRect.left = iX;
        ScreenRect.top = iY;
        ScreenRect.right = iDX + iX;
        ScreenRect.bottom = iDY + iY;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = iDX;
        ViewportRect.bottom = iDY;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    }
    if (DX.DDSScreenPic) DisplayPic();
}

////////////////////////////////////////////////////////////////////////
void NoStretchedBlit3x(void) {
    static int iOldDX = 0;
    static int iOldDY = 0;

    int iX, iY, iDX, iDY;
    int iDX2 = PreviousPSXDisplay.DisplayMode.x;
    int iDY2 = PreviousPSXDisplay.DisplayMode.y;

    if (PreviousPSXDisplay.DisplayMode.x <= 512) {
        iDX2 *= 3;
        iDY2 *= 3;
    }

    iX = iResX - iDX2;
    iY = iResY - iDY2;

    if (iX < 0) {
        iX = 0;
        iDX = iResX;
    } else {
        iX = iX / 2;
        iDX = iDX2;
    }

    if (iY < 0) {
        iY = 0;
        iDY = iResY;
    } else {
        iY = iY / 2;
        iDY = iDY2;
    }

    if (iOldDX != iDX || iOldDY != iDY) {
        DDBLTFX ddbltfx;
        ddbltfx.dwSize = sizeof(ddbltfx);
        ddbltfx.dwFillColor = 0x00000000;
        IDirectDrawSurface_Blt(DX.DDSPrimary, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);
        iOldDX = iDX;
        iOldDY = iDY;
    }

    if (iWindowMode) {
        RECT ScreenRect, ViewportRect;
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);
        Point.x += iX;
        Point.y += iY;

        ScreenRect.left = Point.x;
        ScreenRect.top = Point.y;
        ScreenRect.right = iDX + Point.x;
        ScreenRect.bottom = iDY + Point.y;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = iDX;
        ViewportRect.bottom = iDY;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    } else {
        RECT ScreenRect, ViewportRect;

        ScreenRect.left = iX;
        ScreenRect.top = iY;
        ScreenRect.right = iDX + iX;
        ScreenRect.bottom = iDY + iY;

        ViewportRect.left = 0;
        ViewportRect.top = 0;
        ViewportRect.right = iDX;
        ViewportRect.bottom = iDY;

        WaitVBlank();
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
    }
    if (DX.DDSScreenPic) DisplayPic();
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

void ShowGunCursor(unsigned char *surf) {
    unsigned short dx = (unsigned short)PreviousPSXDisplay.Range.x1;
    unsigned short dy = (unsigned short)PreviousPSXDisplay.DisplayMode.y;
    int x, y, iPlayer, sx, ex, sy, ey;

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * ddsd.lPitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    if (iUseNoStretchBlt >= 3 && iUseNoStretchBlt < 13)  // 2xsai is twice as big, of course
    {
        dx *= 2;
        dy *= 2;
    } else if (iUseNoStretchBlt >= 13) {
        dx *= 3;
        dy *= 3;
    }

    if (iDesktopCol == 32)  // 32 bit color depth
    {
        const unsigned long crCursorColor32[8] = {0xffff0000, 0xff00ff00, 0xff0000ff, 0xffff00ff,
                                                  0xffffff00, 0xff00ffff, 0xffffffff, 0xff7f7f7f};

        surf += PreviousPSXDisplay.Range.x0 << 2;  // -> add x left border

        for (iPlayer = 0; iPlayer < 8; iPlayer++)  // -> loop all possible players
        {
            if (usCursorActive & (1 << iPlayer))  // -> player active?
            {
                const int ty =
                    (ptCursorPoint[iPlayer].y * dy) / 256;  // -> calculate the cursor pos in the current display
                const int tx = (ptCursorPoint[iPlayer].x * dx) / 512;
                sx = tx - 5;
                if (sx < 0) {
                    if (sx & 1)
                        sx = 1;
                    else
                        sx = 0;
                }
                sy = ty - 5;
                if (sy < 0) {
                    if (sy & 1)
                        sy = 1;
                    else
                        sy = 0;
                }
                ex = tx + 6;
                if (ex > dx) ex = dx;
                ey = ty + 6;
                if (ey > dy) ey = dy;

                for (x = tx, y = sy; y < ey; y += 2)  // -> do dotted y line
                    *((unsigned long *)((surf) + (y * ddsd.lPitch) + x * 4)) = crCursorColor32[iPlayer];
                for (y = ty, x = sx; x < ex; x += 2)  // -> do dotted x line
                    *((unsigned long *)((surf) + (y * ddsd.lPitch) + x * 4)) = crCursorColor32[iPlayer];
            }
        }
    } else  // 16 bit color depth
    {
        const unsigned short crCursorColor16[8] = {0xf800, 0x07c0, 0x001f, 0xf81f, 0xffc0, 0x07ff, 0xffff, 0x7bdf};

        surf += PreviousPSXDisplay.Range.x0 << 1;  // -> same stuff as above

        for (iPlayer = 0; iPlayer < 8; iPlayer++) {
            if (usCursorActive & (1 << iPlayer)) {
                const int ty = (ptCursorPoint[iPlayer].y * dy) / 256;
                const int tx = (ptCursorPoint[iPlayer].x * dx) / 512;
                sx = tx - 5;
                if (sx < 0) {
                    if (sx & 1)
                        sx = 1;
                    else
                        sx = 0;
                }
                sy = ty - 5;
                if (sy < 0) {
                    if (sy & 1)
                        sy = 1;
                    else
                        sy = 0;
                }
                ex = tx + 6;
                if (ex > dx) ex = dx;
                ey = ty + 6;
                if (ey > dy) ey = dy;

                for (x = tx, y = sy; y < ey; y += 2)
                    *((unsigned short *)((surf) + (y * ddsd.lPitch) + x * 2)) = crCursorColor16[iPlayer];
                for (y = ty, x = sx; x < ex; x += 2)
                    *((unsigned short *)((surf) + (y * ddsd.lPitch) + x * 2)) = crCursorColor16[iPlayer];
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////

void DoBufferSwap(void)  // SWAP BUFFERS
{                        // (we don't swap... we blit only)
    HRESULT ddrval;
    long x, y;

    return;

    ddrval = IDirectDrawSurface_Lock(DX.DDSRender, NULL, &ddsd, DDLOCK_WAIT | DDLOCK_WRITEONLY, NULL);

    if (ddrval == DDERR_SURFACELOST) {
        IDirectDrawSurface_Restore(DX.DDSRender);
    }

    if (ddrval != DD_OK) {
        IDirectDrawSurface_Unlock(DX.DDSRender, &ddsd);
        return;
    }

    //----------------------------------------------------//

    x = PSXDisplay.DisplayPosition.x;
    y = PSXDisplay.DisplayPosition.y;

    //----------------------------------------------------//

    BlitScreen((unsigned char *)ddsd.lpSurface, x, y);  // fill DDSRender surface

    if (usCursorActive) ShowGunCursor((unsigned char *)ddsd.lpSurface);

    IDirectDrawSurface_Unlock(DX.DDSRender, &ddsd);

    if (ulKeybits & KEY_SHOWFPS) DisplayText();  // paint menu text

    if (pExtraBltFunc) {
        pExtraBltFunc();
        return;
    }

    if (iWindowMode) {
        RECT ScreenRect, ViewportRect;
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);

        ScreenRect.left = Point.x;
        ScreenRect.top = Point.y;
        ScreenRect.right = iResX + Point.x;
        ScreenRect.bottom = iResY + Point.y;

        ViewportRect.left = 0;
        ViewportRect.top = 0;

        if (iDebugMode) {
            if (iFVDisplay) {
                ViewportRect.right = 1024;
                ViewportRect.bottom = iGPUHeight;
            } else {
                ViewportRect.right = PreviousPSXDisplay.DisplayMode.x;
                ViewportRect.bottom = PreviousPSXDisplay.DisplayMode.y;
            }
        } else {
            ViewportRect.right = PreviousPSXDisplay.DisplayMode.x;
            ViewportRect.bottom = PreviousPSXDisplay.DisplayMode.y;

            if (iRumbleTime) {
                ScreenRect.left += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                ScreenRect.right += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                ScreenRect.top += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                ScreenRect.bottom += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                iRumbleTime--;
            }
        }

        if (iUseScanLines == 2)  // stupid nvidia scanline mode
        {
            RECT HelperRect = {0, 0, iResX, iResY};

            WaitVBlank();

            IDirectDrawSurface_Blt(DX.DDSHelper, &HelperRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSHelper, &HelperRect, DDBLT_WAIT, NULL);
        } else {
            WaitVBlank();
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
        }
    } else {
        RECT ScreenRect = {0, 0, iResX, iResY},
             ViewportRect = {0, 0, PreviousPSXDisplay.DisplayMode.x, PreviousPSXDisplay.DisplayMode.y};

        if (iDebugMode && iFVDisplay) {
            ViewportRect.right = 1024;
            ViewportRect.bottom = iGPUHeight;
        } else {
            if (iRumbleTime) {
                ScreenRect.left += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                ScreenRect.right += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                ScreenRect.top += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                ScreenRect.bottom += ((rand() * iRumbleVal) / RAND_MAX) - (iRumbleVal / 2);
                iRumbleTime--;
            }
        }

        if (iUseScanLines == 2)  // stupid nvidia scanline mode
        {
            WaitVBlank();

            IDirectDrawSurface_Blt(DX.DDSHelper, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSHelper, &ScreenRect, DDBLT_WAIT, NULL);
        } else {
            WaitVBlank();
            IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSRender, &ViewportRect, DDBLT_WAIT, NULL);
        }
    }

    if (DX.DDSScreenPic) DisplayPic();
}

////////////////////////////////////////////////////////////////////////
// GAMMA
////////////////////////////////////////////////////////////////////////

int iUseGammaVal = 2048;

void DXSetGamma(void) {
    float g;
    if (iUseGammaVal == 2048) return;

    g = (float)iUseGammaVal;
    if (g > 512) g = ((g - 512) * 2) + 512;
    g = 0.5f + ((g) / 1024.0f);

    // some cards will cheat... so we don't trust the caps here
    // if (DD_Caps.dwCaps2 & DDCAPS2_PRIMARYGAMMA)
    {
        float f;
        DDGAMMARAMP ramp;
        int i;
        LPDIRECTDRAWGAMMACONTROL DD_Gamma = NULL;

//        if
//            FAILED(IDirectDrawSurface_QueryInterface(DX.DDSPrimary, &IID_IDirectDrawGammaControl, (void **)&DD_Gamma))
//        return;

        for (i = 0; i < 256; i++) {
            f = (((float)(i * 256)) * g);
            if (f > 65535) f = 65535;
            ramp.red[i] = ramp.green[i] = ramp.blue[i] = (WORD)f;
        }

        IDirectDrawGammaControl_SetGammaRamp(DD_Gamma, 0, &ramp);
        IDirectDrawGammaControl_Release(DD_Gamma);
    }
}

////////////////////////////////////////////////////////////////////////
// SCAN LINE STUFF
////////////////////////////////////////////////////////////////////////

void SetScanLineList(LPDIRECTDRAWCLIPPER Clipper) {
    LPRGNDATA lpCL;
    RECT *pr;
    int y;
    POINT Point = {0, 0};

    IDirectDrawClipper_SetClipList(Clipper, NULL, 0);

    lpCL = (LPRGNDATA)malloc(sizeof(RGNDATAHEADER) + ((iResY / 2) + 1) * sizeof(RECT));
    if (iWindowMode) ClientToScreen(DX.hWnd, &Point);

    lpCL->rdh.dwSize = sizeof(RGNDATAHEADER);
    lpCL->rdh.iType = RDH_RECTANGLES;
    lpCL->rdh.nCount = iResY / 2;
    lpCL->rdh.nRgnSize = 0;
    lpCL->rdh.rcBound.left = Point.x;
    lpCL->rdh.rcBound.top = Point.y;
    lpCL->rdh.rcBound.bottom = Point.y + iResY;
    lpCL->rdh.rcBound.right = Point.x + iResX;

    pr = (RECT *)lpCL->Buffer;
    for (y = 0; y < iResY; y += 2) {
        pr->left = Point.x;
        pr->top = Point.y + y;
        pr->right = Point.x + iResX;
        pr->bottom = Point.y + y + 1;
        pr++;
    }

    IDirectDrawClipper_SetClipList(Clipper, lpCL, 0);

    free(lpCL);
}

////////////////////////////////////////////////////////////////////////

void MoveScanLineArea(HWND hwnd) {
    LPDIRECTDRAWCLIPPER Clipper;
    HRESULT h;
    DDBLTFX ddbltfx;
    RECT r;

    if (FAILED(h = IDirectDraw_CreateClipper(DX.DD, 0, &Clipper, NULL))) return;

    IDirectDrawSurface_SetClipper(DX.DDSPrimary, NULL);

    ddbltfx.dwSize = sizeof(ddbltfx);
    ddbltfx.dwFillColor = 0x00000000;

    GetClientRect(hwnd, &r);
    ClientToScreen(hwnd, (LPPOINT)&r.left);
    r.right += r.left;
    r.bottom += r.top;

    IDirectDrawSurface_Blt(DX.DDSPrimary, &r, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);

    SetScanLineList(Clipper);

    IDirectDrawSurface_SetClipper(DX.DDSPrimary, Clipper);
    IDirectDrawClipper_Release(Clipper);
}

////////////////////////////////////////////////////////////////////////
// MAIN DIRECT DRAW INIT
////////////////////////////////////////////////////////////////////////

BOOL ReStart = FALSE;

int DXinitialize() {
#if 0
    LPDIRECTDRAW DD;
    int i;
    LPDIRECTDRAWCLIPPER Clipper;
    HRESULT h;
    GUID FAR *guid = 0;
    unsigned char *c;
    DDSCAPS ddscaps;
    DDBLTFX ddbltfx;
    DDPIXELFORMAT dd;
    HRESULT(WINAPI * pDDrawCreateFn)(GUID *, LPDIRECTDRAW *, IUnknown *);

    // init some DX vars
    DX.hWnd = (HWND)hWGPU;
    DX.DDSHelper = 0;
    DX.DDSScreenPic = 0;

    // make guid !
    c = (unsigned char *)&guiDev;
    for (i = 0; i < sizeof(GUID); i++, c++) {
        if (*c) {
            guid = &guiDev;
            break;
        }
    }

    pDDrawCreateFn = (LPVOID)GetProcAddress(hDDrawDLL, "DirectDrawCreate");

    // create dd
    if (pDDrawCreateFn == NULL || pDDrawCreateFn(guid, &DD, 0)) {
        MessageBox(NULL, "This GPU requires DirectX!", "Error", MB_OK);
        return 0;
    }

    DX.DD = DD;

    //////////////////////////////////////////////////////// co-op level

    if (iWindowMode)  // win mode?
    {
        if (IDirectDraw_SetCooperativeLevel(DX.DD, DX.hWnd, DDSCL_NORMAL)) return 0;
    } else {
        if (ReStart) {
            if (IDirectDraw_SetCooperativeLevel(DX.DD, DX.hWnd, DDSCL_NORMAL | DDSCL_FULLSCREEN | DDSCL_FPUSETUP))
                return 0;
        } else {
            if (IDirectDraw_SetCooperativeLevel(DX.DD, DX.hWnd, DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN | DDSCL_FPUSETUP))
                return 0;
        }

        if (0) {  // (iRefreshRate) {
#if 0
            LPDIRECTDRAW2 DD2;
            IDirectDraw_QueryInterface(DX.DD, &IID_IDirectDraw2, (LPVOID *)&DD2);
            if (IDirectDraw2_SetDisplayMode(DD2, iResX, iResY, iColDepth, iRefreshRate, 0)) return 0;
#endif
        } else {
            if (IDirectDraw_SetDisplayMode(DX.DD, iResX, iResY, iColDepth)) return 0;
        }
    }

    //////////////////////////////////////////////////////// main surfaces

    memset(&ddsd, 0, sizeof(DDSURFACEDESC));
    memset(&ddscaps, 0, sizeof(DDSCAPS));
    ddsd.dwSize = sizeof(DDSURFACEDESC);

    ddsd.dwFlags = DDSD_CAPS;  // front buffer

    if (iSysMemory)
        ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_SYSTEMMEMORY;
    else
        ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_VIDEOMEMORY;

    // ddsd.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;//|DDSCAPS_VIDEOMEMORY;
    if (IDirectDraw_CreateSurface(DX.DD, &ddsd, &DX.DDSPrimary, NULL)) return 0;

    //----------------------------------------------------//
    if (iSysMemory && iUseScanLines == 2) iUseScanLines = 1;  // pete: nvidia hack not needed on system mem

    if (iUseScanLines == 2)  // special nvidia hack
    {
        memset(&ddsd, 0, sizeof(DDSURFACEDESC));
        ddsd.dwSize = sizeof(DDSURFACEDESC);
        ddsd.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS;
        ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;
        ddsd.dwWidth = iResX;
        ddsd.dwHeight = iResY;

        if (IDirectDraw_CreateSurface(DX.DD, &ddsd, &DX.DDSHelper, NULL)) return 0;
    }
    //----------------------------------------------------//

    memset(&ddsd, 0, sizeof(DDSURFACEDESC));  // back buffer
    ddsd.dwSize = sizeof(DDSURFACEDESC);
    ddsd.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS;
    // ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;//|DDSCAPS_VIDEOMEMORY;
    if (iSysMemory)
        ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY;
    else
        ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY;

    if (iDebugMode || iUseNoStretchBlt >= 3)
        ddsd.dwWidth = 1024;
    else
        ddsd.dwWidth = 640;

    if (iUseNoStretchBlt >= 3)
        ddsd.dwHeight = 1024;
    else {
        if (iDebugMode)
            ddsd.dwHeight = iGPUHeight;
        else
            ddsd.dwHeight = 512;
    }

    if (IDirectDraw_CreateSurface(DX.DD, &ddsd, &DX.DDSRender, NULL)) return 0;

    // check for desktop color depth
    dd.dwSize = sizeof(DDPIXELFORMAT);
    IDirectDrawSurface_GetPixelFormat(DX.DDSRender, &dd);

    if (dd.dwRBitMask == 0x00007c00 && dd.dwGBitMask == 0x000003e0 && dd.dwBBitMask == 0x0000001f) {
        if (iUseNoStretchBlt >= 3)
            BlitScreen = BlitScreen15_2xSaI;
        else
            BlitScreen = BlitScreen15;
        iDesktopCol = 15;
    } else if (dd.dwRBitMask == 0x0000f800 && dd.dwGBitMask == 0x000007e0 && dd.dwBBitMask == 0x0000001f) {
        if (iUseNoStretchBlt < 4)
            BlitScreen = BlitScreen16;
        else if (iUseNoStretchBlt < 13)
            BlitScreen = BlitScreen16_2xSaI;
        else
            BlitScreen = BlitScreen16_3xSaI;
        iDesktopCol = 16;
    } else {
        if (iUseNoStretchBlt < 4)
            BlitScreen = BlitScreen32;
        else if (iUseNoStretchBlt < 13)
            BlitScreen = BlitScreen32_2xSaI;
        else
            BlitScreen = BlitScreen32_3xSaI;
        iDesktopCol = 32;
    }

    //////////////////////////////////////////////////////// extra blts

    switch (iUseNoStretchBlt) {
        case 1:
            pExtraBltFunc = NoStretchedBlit;
            p2XSaIFunc = NULL;
            break;
        case 2:
            pExtraBltFunc = NoStretchedBlitEx;
            p2XSaIFunc = NULL;
            break;
        case 3:
            pExtraBltFunc = StretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Std2xSaI_ex5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Std2xSaI_ex6;
            else
                p2XSaIFunc = Std2xSaI_ex8;
            break;
        case 4:
            pExtraBltFunc = NoStretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Std2xSaI_ex5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Std2xSaI_ex6;
            else
                p2XSaIFunc = Std2xSaI_ex8;
            break;
        case 5:
            pExtraBltFunc = StretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Super2xSaI_ex5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Super2xSaI_ex6;
            else
                p2XSaIFunc = Super2xSaI_ex8;
            break;
        case 6:
            pExtraBltFunc = NoStretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Super2xSaI_ex5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Super2xSaI_ex6;
            else
                p2XSaIFunc = Super2xSaI_ex8;
            break;
        case 7:
            pExtraBltFunc = StretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = SuperEagle_ex5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = SuperEagle_ex6;
            else
                p2XSaIFunc = SuperEagle_ex8;
            break;
        case 8:
            pExtraBltFunc = NoStretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = SuperEagle_ex5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = SuperEagle_ex6;
            else
                p2XSaIFunc = SuperEagle_ex8;
            break;
        case 9:
            pExtraBltFunc = StretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Scale2x_ex6_5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Scale2x_ex6_5;
            else
                p2XSaIFunc = Scale2x_ex8;
            break;
        case 10:
            pExtraBltFunc = NoStretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Scale2x_ex6_5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Scale2x_ex6_5;
            else
                p2XSaIFunc = Scale2x_ex8;
            break;
        case 11:
            pExtraBltFunc = NoStretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = hq2x;
            else if (iDesktopCol == 16)
                p2XSaIFunc = hq2x;
            else
                p2XSaIFunc = hq2x_32;
            break;
        case 12:
            pExtraBltFunc = StretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = hq2x;
            else if (iDesktopCol == 16)
                p2XSaIFunc = hq2x;
            else
                p2XSaIFunc = hq2x_32;
            break;
        case 13:
            pExtraBltFunc = StretchedBlit2x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Scale3x_ex6_5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Scale3x_ex6_5;
            else
                p2XSaIFunc = Scale3x_ex8;
            break;
        case 14:
            pExtraBltFunc = NoStretchedBlit3x;
            if (iDesktopCol == 15)
                p2XSaIFunc = Scale3x_ex6_5;
            else if (iDesktopCol == 16)
                p2XSaIFunc = Scale3x_ex6_5;
            else
                p2XSaIFunc = Scale3x_ex8;
            break;
        case 15:
            pExtraBltFunc = NoStretchedBlit3x;
            if (iDesktopCol == 15)
                p2XSaIFunc = hq3x_16;
            else if (iDesktopCol == 16)
                p2XSaIFunc = hq3x_16;
            else
                p2XSaIFunc = hq3x_32;
            break;
        default:
            pExtraBltFunc = NULL;
            p2XSaIFunc = NULL;
            break;
    }

    //////////////////////////////////////////////////////// clipper init

    if (FAILED(h = IDirectDraw_CreateClipper(DX.DD, 0, &Clipper, NULL))) return 0;

    if (iUseScanLines)
        SetScanLineList(Clipper);
    else
        IDirectDrawClipper_SetHWnd(Clipper, 0, DX.hWnd);

    IDirectDrawSurface_SetClipper(DX.DDSPrimary, Clipper);
    IDirectDrawClipper_Release(Clipper);

    //////////////////////////////////////////////////////// small screen clean up

    DXSetGamma();

    ddbltfx.dwSize = sizeof(ddbltfx);
    ddbltfx.dwFillColor = 0x00000000;

    IDirectDrawSurface_Blt(DX.DDSPrimary, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);
    IDirectDrawSurface_Blt(DX.DDSRender, NULL, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);

    //////////////////////////////////////////////////////// finish init

    if (iUseNoStretchBlt >= 3) {
        pSaISmallBuff = malloc(512 * 512 * 4);
        memset(pSaISmallBuff, 0, 512 * 512 * 4);
        pSaIBigBuff = malloc(1024 * 1024 * 4);
        memset(pSaIBigBuff, 0, 1024 * 1024 * 4);
    }

    bUsingTWin = FALSE;

    InitMenu();  // menu init

    if (iShowFPS)  // fps on startup
    {
        ulKeybits |= KEY_SHOWFPS;
        szDispBuf[0] = 0;
        BuildDispMenu(0);
    }

    bIsFirstFrame = FALSE;  // done

    return 0;
#endif
}

////////////////////////////////////////////////////////////////////////
// clean up DX stuff
////////////////////////////////////////////////////////////////////////

void DXcleanup()  // DX CLEANUP
{
    CloseMenu();  // bye display lists

    if (iUseNoStretchBlt >= 3) {
        if (pSaISmallBuff) free(pSaISmallBuff);
        pSaISmallBuff = NULL;
        if (pSaIBigBuff) free(pSaIBigBuff);
        pSaIBigBuff = NULL;
    }

    if (!bIsFirstFrame) {
        if (DX.DDSHelper) IDirectDrawSurface_Release(DX.DDSHelper);
        DX.DDSHelper = 0;
        if (DX.DDSScreenPic) IDirectDrawSurface_Release(DX.DDSScreenPic);
        DX.DDSScreenPic = 0;
        IDirectDrawSurface_Release(DX.DDSRender);
        IDirectDrawSurface_Release(DX.DDSPrimary);
        IDirectDraw_SetCooperativeLevel(DX.DD, DX.hWnd, DDSCL_NORMAL);
        IDirectDraw_RestoreDisplayMode(DX.DD);
        IDirectDraw_Release(DX.DD);

        ReStart = TRUE;
        bIsFirstFrame = TRUE;
    }
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

DWORD dwGPUStyle = 0;  // vars to store some wimdows stuff
HANDLE hGPUMenu = NULL;

unsigned long ulInitDisplay(void) {
    HDC hdc;
    RECT r;

    if (iWindowMode)  // win mode?
    {
        DWORD dw = GetWindowLong(hWGPU, GWL_STYLE);  // -> adjust wnd style
        dwGPUStyle = dw;
        dw &= ~WS_THICKFRAME;
        dw |= WS_BORDER | WS_CAPTION;
        SetWindowLong(hWGPU, GWL_STYLE, dw);

        iResX = LOWORD(iWinSize);
        iResY = HIWORD(iWinSize);
        ShowWindow(hWGPU, SW_SHOWNORMAL);

        if (iUseScanLines) SetWindowPos(hWGPU, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

        MoveWindow(hWGPU,  // -> move wnd
                   GetSystemMetrics(SM_CXFULLSCREEN) / 2 - iResX / 2, GetSystemMetrics(SM_CYFULLSCREEN) / 2 - iResY / 2,
                   iResX + GetSystemMetrics(SM_CXFIXEDFRAME) + 3,
                   iResY + GetSystemMetrics(SM_CYFIXEDFRAME) + GetSystemMetrics(SM_CYCAPTION) + 3, TRUE);
        UpdateWindow(hWGPU);  // -> let windows do some update
    } else                    // no window mode:
    {
        DWORD dw = GetWindowLong(hWGPU, GWL_STYLE);  // -> adjust wnd style
        dwGPUStyle = dw;
        hGPUMenu = GetMenu(hWGPU);

        dw &= ~(WS_THICKFRAME | WS_BORDER | WS_CAPTION);
        SetWindowLong(hWGPU, GWL_STYLE, dw);
        SetMenu(hWGPU, NULL);

        ShowWindow(hWGPU, SW_SHOWMAXIMIZED);  // -> max mode
    }

    r.left = r.top = 0;
    r.right = iResX;
    r.bottom = iResY;  // init bkg with black
    hdc = GetDC(hWGPU);
    FillRect(hdc, &r, (HBRUSH)GetStockObject(BLACK_BRUSH));
    ReleaseDC(hWGPU, hdc);

    DXinitialize();  // init direct draw (not D3D... oh, well)

    if (!iWindowMode)                         // fullscreen mode?
        ShowWindow(hWGPU, SW_SHOWMAXIMIZED);  // -> maximize again (fixes strange DX behavior)

    return 1;
}

////////////////////////////////////////////////////////////////////////

void CloseDisplay(void) {
    DXcleanup();  // cleanup dx

    SetWindowLong(hWGPU, GWL_STYLE, dwGPUStyle);  // repair window
    if (hGPUMenu) SetMenu(hWGPU, (HMENU)hGPUMenu);
}

////////////////////////////////////////////////////////////////////////

void CreatePic(unsigned char *pMem) {
    DDSURFACEDESC xddsd;
    HRESULT ddrval;
    unsigned char *ps;
    int x, y;

    memset(&xddsd, 0, sizeof(DDSURFACEDESC));
    xddsd.dwSize = sizeof(DDSURFACEDESC);
    xddsd.dwFlags = DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS;
    // xddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;

    if (iSysMemory)
        xddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY;
    else
        xddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY;

    xddsd.dwWidth = 128;
    xddsd.dwHeight = 96;

    if (IDirectDraw_CreateSurface(DX.DD, &xddsd, &DX.DDSScreenPic, NULL)) {
        DX.DDSScreenPic = 0;
        return;
    }

    ddrval = IDirectDrawSurface_Lock(DX.DDSScreenPic, NULL, &xddsd, DDLOCK_WAIT | DDLOCK_WRITEONLY, NULL);

    if (ddrval == DDERR_SURFACELOST) {
        IDirectDrawSurface_Restore(DX.DDSScreenPic);
    }

    if (ddrval != DD_OK) {
        IDirectDrawSurface_Unlock(DX.DDSScreenPic, &xddsd);
        return;
    }

    ps = (unsigned char *)xddsd.lpSurface;

    if (iDesktopCol == 16) {
        unsigned short s;
        for (y = 0; y < 96; y++) {
            for (x = 0; x < 128; x++) {
                s = (*(pMem + 0)) >> 3;
                s |= ((*(pMem + 1)) & 0xfc) << 3;
                s |= ((*(pMem + 2)) & 0xf8) << 8;
                pMem += 3;
                *((unsigned short *)(ps + y * xddsd.lPitch + x * 2)) = s;
            }
        }
    } else if (iDesktopCol == 15) {
        unsigned short s;
        for (y = 0; y < 96; y++) {
            for (x = 0; x < 128; x++) {
                s = (*(pMem + 0)) >> 3;
                s |= ((*(pMem + 1)) & 0xfc) << 2;
                s |= ((*(pMem + 2)) & 0xf8) << 7;
                pMem += 3;
                *((unsigned short *)(ps + y * xddsd.lPitch + x * 2)) = s;
            }
        }
    } else if (iDesktopCol == 32) {
        unsigned long l;
        for (y = 0; y < 96; y++) {
            for (x = 0; x < 128; x++) {
                l = *(pMem + 0);
                l |= (*(pMem + 1)) << 8;
                l |= (*(pMem + 2)) << 16;
                pMem += 3;
                *((unsigned long *)(ps + y * xddsd.lPitch + x * 4)) = l;
            }
        }
    }

    IDirectDrawSurface_Unlock(DX.DDSScreenPic, &xddsd);
}

///////////////////////////////////////////////////////////////////////////////////////

void DestroyPic(void) {
    if (DX.DDSScreenPic) {
        RECT ScreenRect = {iResX - 128, 0, iResX, 96};
        DDBLTFX ddbltfx;

        if (iWindowMode) {
            POINT Point = {0, 0};
            ClientToScreen(DX.hWnd, &Point);
            ScreenRect.left += Point.x;
            ScreenRect.right += Point.x;
            ScreenRect.top += Point.y;
            ScreenRect.bottom += Point.y;
        }

        ddbltfx.dwSize = sizeof(ddbltfx);
        ddbltfx.dwFillColor = 0x00000000;
        IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, NULL, NULL, DDBLT_COLORFILL, &ddbltfx);

        IDirectDrawSurface_Release(DX.DDSScreenPic);
        DX.DDSScreenPic = 0;
    }
}

///////////////////////////////////////////////////////////////////////////////////////

void DisplayPic(void) {
    RECT ScreenRect = {iResX - 128, 0, iResX, 96}, HelperRect = {0, 0, 128, 96};
    if (iWindowMode) {
        POINT Point = {0, 0};
        ClientToScreen(DX.hWnd, &Point);
        ScreenRect.left += Point.x;
        ScreenRect.right += Point.x;
        ScreenRect.top += Point.y;
        ScreenRect.bottom += Point.y;
    }

    // ??? eh... no need to wait here!
    // WaitVBlank();

    IDirectDrawSurface_Blt(DX.DDSPrimary, &ScreenRect, DX.DDSScreenPic, &HelperRect, DDBLT_WAIT, NULL);
}

///////////////////////////////////////////////////////////////////////////////////////

void ShowGpuPic(void) {
#if 0
    HRSRC hR;
    HGLOBAL hG;
    unsigned long *pRMem;
    unsigned char *pMem;
    int x, y;
    unsigned long *pDMem;

    // turn off any screen pic, if it does already exist
    if (DX.DDSScreenPic) {
        DestroyPic();
        return;
    }

    if (ulKeybits & KEY_SHOWFPS) {
        ShowTextGpuPic();
        return;
    }

    // load and lock the bitmap (lock is kinda obsolete in win32)
    hR = FindResource(hInst, MAKEINTRESOURCE(IDB_GPU), RT_BITMAP);
    hG = LoadResource(hInst, hR);

    // get long ptr to bmp data
    pRMem = ((unsigned long *)LockResource(hG)) + 10;

    // change the data upside-down
    pMem = (unsigned char *)malloc(128 * 96 * 3);

    for (y = 0; y < 96; y++) {
        pDMem = (unsigned long *)(pMem + (95 - y) * 128 * 3);
        for (x = 0; x < 96; x++) *pDMem++ = *pRMem++;
    }

    // show the pic
    CreatePic(pMem);

    // clean up
    free(pMem);
    DeleteObject(hG);
#endif
}

////////////////////////////////////////////////////////////////////////

void ShowTextGpuPic(void)  // CREATE TEXT SCREEN PIC
{                          // gets an Text and paints
    unsigned char *pMem;
    BITMAPINFO bmi;  // it into a rgb24 bitmap
    HDC hdc, hdcMem;
    HBITMAP hBmp, hBmpMem;
    HFONT hFontMem;  // to display it in the gpu
    HBRUSH hBrush, hBrushMem;
    HPEN hPen, hPenMem;
    char szB[256];
    RECT r = {0, 0, 128, 96};               // size of bmp... don't change that
    COLORREF crFrame = RGB(128, 255, 128);  // some example color inits
    COLORREF crBkg = RGB(0, 0, 0);
    COLORREF crText = RGB(0, 255, 0);

    if (DX.DDSScreenPic) DestroyPic();

    //----------------------------------------------------// creation of the dc & bitmap

    hdc = GetDC(NULL);  // create a dc
    hdcMem = CreateCompatibleDC(hdc);
    ReleaseDC(NULL, hdc);

    memset(&bmi, 0, sizeof(BITMAPINFO));  // create a 24bit dib
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = 128;
    bmi.bmiHeader.biHeight = -96;
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biCompression = BI_RGB;
    hBmp = CreateDIBSection(hdcMem, &bmi, DIB_RGB_COLORS, (void **)&pMem, NULL,
                            0);  // pMem will point to 128x96x3 bitmap data

    hBmpMem = (HBITMAP)SelectObject(hdcMem, hBmp);  // sel the bmp into the dc

    //----------------------------------------------------// ok, the following is just a drawing example... change it...
    // create & select an additional font... whatever you want to paint, paint it in the dc :)
    hBrush = CreateSolidBrush(crBkg);
    hPen = CreatePen(PS_SOLID, 0, crFrame);

    hBrushMem = (HBRUSH)SelectObject(hdcMem, hBrush);
    hPenMem = (HPEN)SelectObject(hdcMem, hPen);
    hFontMem = (HFONT)SelectObject(hdcMem, hGFont);

    SetTextColor(hdcMem, crText);
    SetBkColor(hdcMem, crBkg);

    Rectangle(hdcMem, r.left, r.top, r.right, r.bottom);  // our example: fill rect and paint border
    InflateRect(&r, -3, -2);                              // reduce the text area

    // LoadString(hInst, IDS_INFO0 + iMPos, szB, 255);
    // DrawText(hdcMem, szB, strlen(szB), &r,  // paint the text (including clipping and word break)
    //         DT_LEFT | DT_WORDBREAK);

    //----------------------------------------------------// ok, now store the pMem data, or just call the gpu func

    CreatePic(pMem);

    //----------------------------------------------------// finished, now we clean up... needed, or you will get
    // resource leaks :)

    SelectObject(hdcMem, hBmpMem);  // sel old mem dc objects
    SelectObject(hdcMem, hBrushMem);
    SelectObject(hdcMem, hPenMem);
    SelectObject(hdcMem, hFontMem);
    DeleteDC(hdcMem);  // delete mem dcs
    DeleteObject(hBmp);
    DeleteObject(hBrush);  // delete created objects
    DeleteObject(hPen);
}

///////////////////////////////////////////////////////////////////////

static void hqx_init(unsigned bits_per_pixel) { interp_set(bits_per_pixel); }

static void hq2x_16_def(unsigned short *dst0, unsigned short *dst1, const unsigned short *src0,
                        const unsigned short *src1, const unsigned short *src2, unsigned count) {
    unsigned i;

    for (i = 0; i < count; ++i) {
        unsigned char mask;

        unsigned short c[9];

        c[1] = src0[0];
        c[4] = src1[0];
        c[7] = src2[0];

        if (i > 0) {
            c[0] = src0[-1];
            c[3] = src1[-1];
            c[6] = src2[-1];
        } else {
            c[0] = c[1];
            c[3] = c[4];
            c[6] = c[7];
        }

        if (i < count - 1) {
            c[2] = src0[1];
            c[5] = src1[1];
            c[8] = src2[1];
        } else {
            c[2] = c[1];
            c[5] = c[4];
            c[8] = c[7];
        }

        mask = 0;

        if (interp_16_diff(c[0], c[4])) mask |= 1 << 0;
        if (interp_16_diff(c[1], c[4])) mask |= 1 << 1;
        if (interp_16_diff(c[2], c[4])) mask |= 1 << 2;
        if (interp_16_diff(c[3], c[4])) mask |= 1 << 3;
        if (interp_16_diff(c[5], c[4])) mask |= 1 << 4;
        if (interp_16_diff(c[6], c[4])) mask |= 1 << 5;
        if (interp_16_diff(c[7], c[4])) mask |= 1 << 6;
        if (interp_16_diff(c[8], c[4])) mask |= 1 << 7;

#define P0 dst0[0]
#define P1 dst0[1]
#define P2 dst1[0]
#define P3 dst1[1]
#define MUR interp_16_diff(c[1], c[5])
#define MDR interp_16_diff(c[5], c[7])
#define MDL interp_16_diff(c[7], c[3])
#define MUL interp_16_diff(c[3], c[1])
#define IC(p0) c[p0]
#define I11(p0, p1) interp_16_11(c[p0], c[p1])
#define I211(p0, p1, p2) interp_16_211(c[p0], c[p1], c[p2])
#define I31(p0, p1) interp_16_31(c[p0], c[p1])
#define I332(p0, p1, p2) interp_16_332(c[p0], c[p1], c[p2])
#define I431(p0, p1, p2) interp_16_431(c[p0], c[p1], c[p2])
#define I521(p0, p1, p2) interp_16_521(c[p0], c[p1], c[p2])
#define I53(p0, p1) interp_16_53(c[p0], c[p1])
#define I611(p0, p1, p2) interp_16_611(c[p0], c[p1], c[p2])
#define I71(p0, p1) interp_16_71(c[p0], c[p1])
#define I772(p0, p1, p2) interp_16_772(c[p0], c[p1], c[p2])
#define I97(p0, p1) interp_16_97(c[p0], c[p1])
#define I1411(p0, p1, p2) interp_16_1411(c[p0], c[p1], c[p2])
#define I151(p0, p1) interp_16_151(c[p0], c[p1])

        switch (mask) {
#include "hq2x.h"
        }

#undef P0
#undef P1
#undef P2
#undef P3
#undef MUR
#undef MDR
#undef MDL
#undef MUL
#undef IC
#undef I11
#undef I211
#undef I31
#undef I332
#undef I431
#undef I521
#undef I53
#undef I611
#undef I71
#undef I772
#undef I97
#undef I1411
#undef I151

        src0 += 1;
        src1 += 1;
        src2 += 1;
        dst0 += 2;
        dst1 += 2;
    }
}

void hq2x(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height) {
    const int dstPitch = srcPitch;

    int count = height;

    unsigned short *dst0 = (unsigned short *)dstPtr;
    unsigned short *dst1 = dst0 + dstPitch;

    unsigned short *src0 = (unsigned short *)srcPtr;
    unsigned short *src1 = src0 + (srcPitch >> 1);
    unsigned short *src2 = src1 + (srcPitch >> 1);
    hqx_init(16);
    hq2x_16_def(dst0, dst1, src0, src0, src1, width);

    count -= 2;
    while (count) {
        dst0 += dstPitch << 1;
        dst1 += dstPitch << 1;
        hq2x_16_def(dst0, dst1, src0, src1, src2, width);
        src0 = src1;
        src1 = src2;
        src2 += srcPitch >> 1;
        --count;
    }
    dst0 += dstPitch << 1;
    dst1 += dstPitch << 1;
    hq2x_16_def(dst0, dst1, src0, src1, src1, width);
}

///////////////////////////////////////////////////////////////////

static void hq2x_32_def(unsigned long *dst0, unsigned long *dst1, const unsigned long *src0, const unsigned long *src1,
                        const unsigned long *src2, unsigned count) {
    unsigned i;

    for (i = 0; i < count; ++i) {
        unsigned char mask;

        unsigned long c[9];

        c[1] = src0[0];
        c[4] = src1[0];
        c[7] = src2[0];

        if (i > 0) {
            c[0] = src0[-1];
            c[3] = src1[-1];
            c[6] = src2[-1];
        } else {
            c[0] = c[1];
            c[3] = c[4];
            c[6] = c[7];
        }

        if (i < count - 1) {
            c[2] = src0[1];
            c[5] = src1[1];
            c[8] = src2[1];
        } else {
            c[2] = c[1];
            c[5] = c[4];
            c[8] = c[7];
        }

        mask = 0;

        if (interp_32_diff(c[0], c[4])) mask |= 1 << 0;
        if (interp_32_diff(c[1], c[4])) mask |= 1 << 1;
        if (interp_32_diff(c[2], c[4])) mask |= 1 << 2;
        if (interp_32_diff(c[3], c[4])) mask |= 1 << 3;
        if (interp_32_diff(c[5], c[4])) mask |= 1 << 4;
        if (interp_32_diff(c[6], c[4])) mask |= 1 << 5;
        if (interp_32_diff(c[7], c[4])) mask |= 1 << 6;
        if (interp_32_diff(c[8], c[4])) mask |= 1 << 7;

#define P0 dst0[0]
#define P1 dst0[1]
#define P2 dst1[0]
#define P3 dst1[1]
#define MUR interp_32_diff(c[1], c[5])
#define MDR interp_32_diff(c[5], c[7])
#define MDL interp_32_diff(c[7], c[3])
#define MUL interp_32_diff(c[3], c[1])
#define IC(p0) c[p0]
#define I11(p0, p1) interp_32_11(c[p0], c[p1])
#define I211(p0, p1, p2) interp_32_211(c[p0], c[p1], c[p2])
#define I31(p0, p1) interp_32_31(c[p0], c[p1])
#define I332(p0, p1, p2) interp_32_332(c[p0], c[p1], c[p2])
#define I431(p0, p1, p2) interp_32_431(c[p0], c[p1], c[p2])
#define I521(p0, p1, p2) interp_32_521(c[p0], c[p1], c[p2])
#define I53(p0, p1) interp_32_53(c[p0], c[p1])
#define I611(p0, p1, p2) interp_32_611(c[p0], c[p1], c[p2])
#define I71(p0, p1) interp_32_71(c[p0], c[p1])
#define I772(p0, p1, p2) interp_32_772(c[p0], c[p1], c[p2])
#define I97(p0, p1) interp_32_97(c[p0], c[p1])
#define I1411(p0, p1, p2) interp_32_1411(c[p0], c[p1], c[p2])
#define I151(p0, p1) interp_32_151(c[p0], c[p1])

        switch (mask) {
#include "hq2x.h"
        }

#undef P0
#undef P1
#undef P2
#undef P3
#undef MUR
#undef MDR
#undef MDL
#undef MUL
#undef IC
#undef I11
#undef I211
#undef I31
#undef I332
#undef I431
#undef I521
#undef I53
#undef I611
#undef I71
#undef I772
#undef I97
#undef I1411
#undef I151

        src0 += 1;
        src1 += 1;
        src2 += 1;
        dst0 += 2;
        dst1 += 2;
    }
}

void hq2x_32(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height) {
    const int dstPitch = srcPitch << 1;

    int count = height;

    unsigned long *dst0 = (unsigned long *)dstPtr;
    unsigned long *dst1 = dst0 + (dstPitch >> 2);

    unsigned long *src0 = (unsigned long *)srcPtr;
    unsigned long *src1 = src0 + (srcPitch >> 2);
    unsigned long *src2 = src1 + (srcPitch >> 2);
    hq2x_32_def(dst0, dst1, src0, src0, src1, width);

    count -= 2;
    while (count) {
        dst0 += dstPitch >> 1;
        dst1 += dstPitch >> 1;
        hq2x_32_def(dst0, dst1, src0, src1, src2, width);
        src0 = src1;
        src1 = src2;
        src2 += srcPitch >> 2;
        --count;
    }
    dst0 += dstPitch >> 1;
    dst1 += dstPitch >> 1;
    hq2x_32_def(dst0, dst1, src0, src1, src1, width);
}

static void hq3x_32_def(unsigned long *dst0, unsigned long *dst1, unsigned long *dst2, const unsigned long *src0,
                        const unsigned long *src1, const unsigned long *src2, unsigned count) {
    unsigned i;

    for (i = 0; i < count; ++i) {
        unsigned char mask;

        unsigned long c[9];

        c[1] = src0[0];
        c[4] = src1[0];
        c[7] = src2[0];

        if (i > 0) {
            c[0] = src0[-1];
            c[3] = src1[-1];
            c[6] = src2[-1];
        } else {
            c[0] = c[1];
            c[3] = c[4];
            c[6] = c[7];
        }

        if (i < count - 1) {
            c[2] = src0[1];
            c[5] = src1[1];
            c[8] = src2[1];
        } else {
            c[2] = c[1];
            c[5] = c[4];
            c[8] = c[7];
        }

        mask = 0;

        if (interp_32_diff(c[0], c[4])) mask |= 1 << 0;
        if (interp_32_diff(c[1], c[4])) mask |= 1 << 1;
        if (interp_32_diff(c[2], c[4])) mask |= 1 << 2;
        if (interp_32_diff(c[3], c[4])) mask |= 1 << 3;
        if (interp_32_diff(c[5], c[4])) mask |= 1 << 4;
        if (interp_32_diff(c[6], c[4])) mask |= 1 << 5;
        if (interp_32_diff(c[7], c[4])) mask |= 1 << 6;
        if (interp_32_diff(c[8], c[4])) mask |= 1 << 7;

#define P0 dst0[0]
#define P1 dst0[1]
#define P2 dst0[2]
#define P3 dst1[0]
#define P4 dst1[1]
#define P5 dst1[2]
#define P6 dst2[0]
#define P7 dst2[1]
#define P8 dst2[2]
#define MUR interp_32_diff(c[1], c[5])
#define MDR interp_32_diff(c[5], c[7])
#define MDL interp_32_diff(c[7], c[3])
#define MUL interp_32_diff(c[3], c[1])
#define IC(p0) c[p0]
#define I11(p0, p1) interp_32_11(c[p0], c[p1])
#define I211(p0, p1, p2) interp_32_211(c[p0], c[p1], c[p2])
#define I31(p0, p1) interp_32_31(c[p0], c[p1])
#define I332(p0, p1, p2) interp_32_332(c[p0], c[p1], c[p2])
#define I431(p0, p1, p2) interp_32_431(c[p0], c[p1], c[p2])
#define I521(p0, p1, p2) interp_32_521(c[p0], c[p1], c[p2])
#define I53(p0, p1) interp_32_53(c[p0], c[p1])
#define I611(p0, p1, p2) interp_32_611(c[p0], c[p1], c[p2])
#define I71(p0, p1) interp_32_71(c[p0], c[p1])
#define I772(p0, p1, p2) interp_32_772(c[p0], c[p1], c[p2])
#define I97(p0, p1) interp_32_97(c[p0], c[p1])
#define I1411(p0, p1, p2) interp_32_1411(c[p0], c[p1], c[p2])
#define I151(p0, p1) interp_32_151(c[p0], c[p1])

        switch (mask) {
#include "hq3x.h"
        }

#undef P0
#undef P1
#undef P2
#undef P3
#undef P4
#undef P5
#undef P6
#undef P7
#undef P8
#undef MUR
#undef MDR
#undef MDL
#undef MUL
#undef IC
#undef I11
#undef I211
#undef I31
#undef I332
#undef I431
#undef I521
#undef I53
#undef I611
#undef I71
#undef I772
#undef I97
#undef I1411
#undef I151

        src0 += 1;
        src1 += 1;
        src2 += 1;
        dst0 += 3;
        dst1 += 3;
        dst2 += 3;
    }
}

void hq3x_32(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height) {
    int count = height;

    int dstPitch = srcPitch >> 1;

    unsigned long *dst0 = (unsigned long *)dstPtr;
    unsigned long *dst1 = dst0 + dstPitch;
    unsigned long *dst2 = dst1 + dstPitch;

    unsigned long *src0 = (unsigned long *)srcPtr;
    unsigned long *src1 = src0 + (srcPitch >> 2);
    unsigned long *src2 = src1 + (srcPitch >> 2);
    hq3x_32_def(dst0, dst1, dst2, src0, src0, src2, width);

    count -= 2;
    while (count) {
        dst0 += dstPitch * 3;
        dst1 += dstPitch * 3;
        dst2 += dstPitch * 3;

        hq3x_32_def(dst0, dst1, dst2, src0, src1, src2, width);
        src0 = src1;
        src1 = src2;
        src2 += srcPitch >> 2;
        --count;
    }
    dst0 += dstPitch * 3;
    dst1 += dstPitch * 3;
    dst2 += dstPitch * 3;

    hq3x_32_def(dst0, dst1, dst2, src0, src1, src1, width);
}

static void hq3x_16_def(unsigned short *dst0, unsigned short *dst1, unsigned short *dst2, const unsigned short *src0,
                        const unsigned short *src1, const unsigned short *src2, unsigned count) {
    unsigned i;

    for (i = 0; i < count; ++i) {
        unsigned char mask;

        unsigned short c[9];

        c[1] = src0[0];
        c[4] = src1[0];
        c[7] = src2[0];

        if (i > 0) {
            c[0] = src0[-1];
            c[3] = src1[-1];
            c[6] = src2[-1];
        } else {
            c[0] = c[1];
            c[3] = c[4];
            c[6] = c[7];
        }

        if (i < count - 1) {
            c[2] = src0[1];
            c[5] = src1[1];
            c[8] = src2[1];
        } else {
            c[2] = c[1];
            c[5] = c[4];
            c[8] = c[7];
        }

        mask = 0;

        if (interp_16_diff(c[0], c[4])) mask |= 1 << 0;
        if (interp_16_diff(c[1], c[4])) mask |= 1 << 1;
        if (interp_16_diff(c[2], c[4])) mask |= 1 << 2;
        if (interp_16_diff(c[3], c[4])) mask |= 1 << 3;
        if (interp_16_diff(c[5], c[4])) mask |= 1 << 4;
        if (interp_16_diff(c[6], c[4])) mask |= 1 << 5;
        if (interp_16_diff(c[7], c[4])) mask |= 1 << 6;
        if (interp_16_diff(c[8], c[4])) mask |= 1 << 7;

#define P0 dst0[0]
#define P1 dst0[1]
#define P2 dst0[2]
#define P3 dst1[0]
#define P4 dst1[1]
#define P5 dst1[2]
#define P6 dst2[0]
#define P7 dst2[1]
#define P8 dst2[2]
#define MUR interp_16_diff(c[1], c[5])
#define MDR interp_16_diff(c[5], c[7])
#define MDL interp_16_diff(c[7], c[3])
#define MUL interp_16_diff(c[3], c[1])
#define IC(p0) c[p0]
#define I11(p0, p1) interp_16_11(c[p0], c[p1])
#define I211(p0, p1, p2) interp_16_211(c[p0], c[p1], c[p2])
#define I31(p0, p1) interp_16_31(c[p0], c[p1])
#define I332(p0, p1, p2) interp_16_332(c[p0], c[p1], c[p2])
#define I431(p0, p1, p2) interp_16_431(c[p0], c[p1], c[p2])
#define I521(p0, p1, p2) interp_16_521(c[p0], c[p1], c[p2])
#define I53(p0, p1) interp_16_53(c[p0], c[p1])
#define I611(p0, p1, p2) interp_16_611(c[p0], c[p1], c[p2])
#define I71(p0, p1) interp_16_71(c[p0], c[p1])
#define I772(p0, p1, p2) interp_16_772(c[p0], c[p1], c[p2])
#define I97(p0, p1) interp_16_97(c[p0], c[p1])
#define I1411(p0, p1, p2) interp_16_1411(c[p0], c[p1], c[p2])
#define I151(p0, p1) interp_16_151(c[p0], c[p1])

        switch (mask) {
#include "hq3x.h"
        }

#undef P0
#undef P1
#undef P2
#undef P3
#undef P4
#undef P5
#undef P6
#undef P7
#undef P8
#undef MUR
#undef MDR
#undef MDL
#undef MUL
#undef IC
#undef I11
#undef I211
#undef I31
#undef I332
#undef I431
#undef I521
#undef I53
#undef I611
#undef I71
#undef I772
#undef I97
#undef I1411
#undef I151

        src0 += 1;
        src1 += 1;
        src2 += 1;
        dst0 += 3;
        dst1 += 3;
        dst2 += 3;
    }
}

void hq3x_16(unsigned char *srcPtr, DWORD srcPitch, unsigned char *dstPtr, int width, int height) {
    int count = height;
    int dstPitch = srcPitch;

    unsigned short *dst0 = (unsigned short *)dstPtr;
    unsigned short *dst1 = dst0 + dstPitch;
    unsigned short *dst2 = dst1 + dstPitch;

    unsigned short *src0 = (unsigned short *)srcPtr;
    unsigned short *src1 = src0 + (srcPitch >> 1);
    unsigned short *src2 = src1 + (srcPitch >> 1);
    hqx_init(16);
    hq3x_16_def(dst0, dst1, dst2, src0, src0, src2, width);

    count -= 2;
    while (count) {
        dst0 += dstPitch * 3;
        dst1 += dstPitch * 3;
        dst2 += dstPitch * 3;

        hq3x_16_def(dst0, dst1, dst2, src0, src1, src2, width);
        src0 = src1;
        src1 = src2;
        src2 += srcPitch >> 1;
        --count;
    }
    dst0 += dstPitch * 3;
    dst1 += dstPitch * 3;
    dst2 += dstPitch * 3;

    hq3x_16_def(dst0, dst1, dst2, src0, src1, src1, width);
}
