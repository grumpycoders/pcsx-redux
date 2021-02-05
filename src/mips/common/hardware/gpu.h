/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include <stdint.h>

#include "common/hardware/hwregs.h"

enum HResolution {
    HR_EXTENDED,
    HR_256 = 0,
    HR_320 = 1,
    HR_512 = 2,
    HR_640 = 3,
};

enum VResolution {
    VR_240 = 0,
    VR_480 = 1,
};

enum VideoMode {
    VM_NTSC = 0,
    VM_PAL = 1,
};

enum ColorDepth {
    CD_15BITS = 0,
    CD_24BITS = 1,
};

enum VideoInterlace {
    VI_OFF = 0,
    VI_ON = 1,
};

enum HResolutionExtended {
    HRE_NORMAL = 0,
    HRE_368 = 1,
};

struct DisplayModeConfig {
    enum HResolution hResolution;
    enum VResolution vResolution;
    enum VideoMode videoMode;
    enum ColorDepth colorDepth;
    enum VideoInterlace videoInterlace;
    enum HResolutionExtended hResolutionExtended;
};

static inline void waitGPU() {
    while ((GPU_STATUS & 0x04000000) == 0)
        ;
}

static inline void sendGPUData(uint32_t status) {
    waitGPU();
    GPU_DATA = status;
}

static inline void sendGPUStatus(uint32_t status) {
    waitGPU();
    GPU_STATUS = status;
}

static inline uint32_t generateDisableDisplay() { return 0x03000001; }
static inline uint32_t generateEnableDisplay() { return 0x03000000; }
static inline void disableDisplay() { sendGPUStatus(generateDisableDisplay()); }
static inline void enableDisplay() { sendGPUStatus(generateEnableDisplay()); }

static inline uint32_t generateDisplayMode(struct DisplayModeConfig* config) {
    return 0x08000000 | (config->hResolution << 0) | (config->vResolution << 2) | (config->videoMode << 3) |
           (config->colorDepth << 4) | (config->videoInterlace << 5) | (config->hResolutionExtended << 6);
}

static inline void setDisplayMode(struct DisplayModeConfig* config) { sendGPUStatus(generateDisplayMode(config)); }

static inline uint32_t generateDisplayArea(int16_t x, int16_t y) { return 0x05000000 | x | (y << 10); }
static inline void setDisplayArea(int16_t x, int16_t y) { sendGPUStatus(generateDisplayArea(x, y)); }

static inline uint32_t generateHorizontalRange(int16_t x1, int16_t x2) {
    return 0x06000000 | (x1 + 0x260) | ((x1 + x2 + 0x260) << 12);
}
static inline void setHorizontalRange(int16_t x1, int16_t x2) { sendGPUStatus(generateHorizontalRange(x1, x2)); }

static inline uint32_t generateVerticalRange(int16_t y1, int16_t y2) { return 0x07000000 | y1 | (y2 << 10); }
static inline void setVerticalRange(int16_t y1, int16_t y2) { sendGPUStatus(generateVerticalRange(y1, y2)); }

union Color {
    uint32_t packed;
    struct {
        uint8_t r, g, b;
    };
};

struct FastFill {
    union Color c;
    int16_t x, y, w, h;
};

static inline void fastFill(struct FastFill* ff) {
    waitGPU();
    GPU_DATA = 0x02000000 | ff->c.r | ff->c.g << 8 | ff->c.b << 16;
    GPU_DATA = ff->x | ff->y << 16;
    GPU_DATA = ff->w | ff->h << 16;
}

static inline uint32_t generateDrawingAreaStart(int16_t x, int16_t y) { return 0xe3000000 | x | y << 10; }
static inline uint32_t generateDrawingAreaEnd(int16_t x, int16_t y) { return 0xe4000000 | (x - 1) | (y - 1) << 10; }
static inline void setDrawingArea(int16_t x1, int16_t y1, int16_t x2, int16_t y2) {
    sendGPUData(generateDrawingAreaStart(x1, y1));
    sendGPUData(generateDrawingAreaEnd(x2, y2));
}

static inline uint32_t generateDrawingOffset(int16_t x, int16_t y) { return 0xe5000000 | x | y << 10; }
static inline void setDrawingOffset(int16_t x, int16_t y) { sendGPUData(generateDrawingOffset(x, y)); }

enum Shading {
    S_FLAT = 0,
    S_GOURAUD = 1,
};

enum VerticesCount {
    VC_3 = 0,
    VC_4 = 1,
};

enum Textured {
    TEX_ON = 1,
    TEX_OFF = 0,
};

enum Transparency {
    TRANS_ON = 1,
    TRANS_OFF = 0,
};

enum Blending {
    BLEND_ON = 1,
    BLEND_OFF = 0,
};

struct GPUPolygonCommand {
    enum Shading shading;
    enum VerticesCount verticesCount;
    enum Textured textured;
    enum Transparency transparency;
    enum Blending blending;
    union Color color;
};

static inline uint32_t generatePolygonCommand(struct GPUPolygonCommand* c) {
    return 0x20000000 | c->shading << 28 | c->verticesCount << 27 | c->textured << 26 | c->transparency << 25 |
           c->blending << 24 | c->color.b << 16 | c->color.g << 8 | c->color.r;
}
static inline void startPolygonCommand(struct GPUPolygonCommand* c) { sendGPUData(generatePolygonCommand(c)); }

enum LineStyle {
    POLY_OFF = 0,
    POLY_ON = 1,
};

struct GPULineCommand {
    enum Shading shading;
    enum LineStyle lineStyle;
    enum Transparency transparency;
    union Color color;
};

static inline uint32_t generateLineCommand(struct GPULineCommand* c) {
    return 0x40000000 | c->shading << 28 | c->lineStyle << 27 | c->transparency << 25 | c->color.b << 16 |
           c->color.g << 8 | c->color.r;
}
static inline void startLineCommand(struct GPULineCommand* c) { sendGPUData(generateLineCommand(c)); }
