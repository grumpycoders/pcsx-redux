
#include "DrawString.h"
#include "DrawStringFont.h"

#define CHAR_W 10
#define CHAR_H 14

void (*drawChar)(char *, int, char, int, int, int);
void (*drawHline)(char *, int, char, int, int, int);

static void drawChar15(char *ptr, int lPitch, char c, int mw, int mh, int mode) {
    int x, y, w, h;
    int fx, fy;
    unsigned short *optr;
    char *fptr;

    if (mw > CHAR_W)
        w = CHAR_W;
    else
        w = mw;
    if (mh > CHAR_H)
        h = CHAR_H;
    else
        h = mh;
    if (w <= 0 || h <= 0) return;

    fx = font_tc[c * 4 + 0] + 2;
    fy = font_tc[c * 4 + 1];

    for (y = 0; y < h; y++) {
        optr = (unsigned short *)(ptr + y * lPitch);
        fptr = font + (fy + y) * 256 + fx;
        for (x = 0; x < w; x++) {
            if (fptr[x])
                optr[x] = 0x03e0;
            else
                optr[x] = 0;
        }
    }
}

static void drawChar16(char *ptr, int lPitch, char c, int mw, int mh, int mode) {
    int x, y, w, h;
    int fx, fy;
    unsigned short *optr;
    char *fptr;

    if (mw > CHAR_W)
        w = CHAR_W;
    else
        w = mw;
    if (mh > CHAR_H)
        h = CHAR_H;
    else
        h = mh;
    if (w <= 0 || h <= 0) return;

    fx = font_tc[c * 4 + 0] + 2;
    fy = font_tc[c * 4 + 1];

    for (y = 0; y < h; y++) {
        optr = (unsigned short *)(ptr + y * lPitch);
        fptr = font + (fy + y) * 256 + fx;
        for (x = 0; x < w; x++) {
            if (fptr[x])
                optr[x] = 0x07e0;
            else
                optr[x] = 0;
        }
    }
}

static void drawChar24(char *ptr, int lPitch, char c, int mw, int mh, int mode) {
    int x, y, w, h;
    int fx, fy;
    unsigned char *optr;
    char *fptr;

    if (mw > CHAR_W)
        w = CHAR_W;
    else
        w = mw;
    if (mh > CHAR_H)
        h = CHAR_H;
    else
        h = mh;
    if (w <= 0 || h <= 0) return;

    fx = font_tc[c * 4 + 0] + 2;
    fy = font_tc[c * 4 + 1];

    for (y = 0; y < h; y++) {
        optr = (unsigned char *)(ptr + y * lPitch);
        fptr = font + (fy + y) * 256 + fx;
        for (x = 0; x < w; x++) {
            optr[x * 3] = 0;
            if (fptr[x])
                optr[x * 3 + 1] = 0xff;
            else
                optr[x + 1] = 0;
            optr[x * 3 + 2] = 0;
        }
    }
}

static void drawChar32(char *ptr, int lPitch, char c, int mw, int mh, int mode) {
    int x, y, w, h;
    int fx, fy;
    unsigned long *optr;
    char *fptr;

    if (mw > CHAR_W)
        w = CHAR_W;
    else
        w = mw;
    if (mh > CHAR_H)
        h = CHAR_H;
    else
        h = mh;
    if (w <= 0 || h <= 0) return;

    fx = font_tc[c * 4 + 0] + 2;
    fy = font_tc[c * 4 + 1];

    for (y = 0; y < h; y++) {
        optr = (unsigned long *)(ptr + y * lPitch);
        fptr = font + (fy + y) * 256 + fx;
        for (x = 0; x < w; x++) {
            if (fptr[x])
                optr[x] = 0x00ff00;
            else
                optr[x] = 0;
        }
    }
}

void DrawString(char *buff, int lPitch, int bpp, int x, int y, int w, int h, char *str, int len, int mode) {
    char *ptr;

    switch (bpp) {
        case 15:
            drawChar = drawChar15;
            bpp = 2;
            break;
        case 16:
            drawChar = drawChar16;
            bpp = 2;
            break;
        case 24:
            drawChar = drawChar24;
            bpp = 3;
            break;
        case 32:
            drawChar = drawChar32;
            bpp = 4;
            break;
        default:
            return;
    }

    w += x;
    h += y;

    while (x < w) {
        ptr = buff + lPitch * y + x * bpp;
        if (len > 0)
            drawChar(ptr, lPitch, *str, w - x, h - y, mode);
        else
            drawChar(ptr, lPitch, ' ', w - x, h - y, mode);
        str++;
        len--;
        x += CHAR_W;
    }
}
