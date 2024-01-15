-- lualoader, R"EOF(--
--   Copyright (C) 2023 PCSX-Redux authors
--
--   This program is free software; you can redistribute it and/or modify
--   it under the terms of the GNU General Public License as published by
--   the Free Software Foundation; either version 2 of the License, or
--   (at your option) any later version.
--
--   This program is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--   GNU General Public License for more details.
--
--   You should have received a copy of the GNU General Public License
--   along with this program; if not, write to the
--   Free Software Foundation, Inc.,
--   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
ffi.cdef [[
typedef struct NVGcontext NVGcontext;

struct NVGcolor {
    union {
        float rgba[4];
        struct {
            float r,g,b,a;
        };
    };
};
typedef struct NVGcolor NVGcolor;

struct NVGpaint {
    float xform[6];
    float extent[2];
    float radius;
    float feather;
    NVGcolor innerColor;
    NVGcolor outerColor;
    int image;
};
typedef struct NVGpaint NVGpaint;

struct NVGglyphPosition {
    const char* str;
    float x;
    float minx, maxx;
};
typedef struct NVGglyphPosition NVGglyphPosition;

struct NVGtextRow {
    const char* start;
    const char* end;
    const char* next;
    float width;
    float minx, maxx;
};
typedef struct NVGtextRow NVGtextRow;

void nvgGlobalCompositeOperation(NVGcontext* ctx, int op);
void nvgGlobalCompositeBlendFunc(NVGcontext* ctx, int sfactor, int dfactor);
void nvgGlobalCompositeBlendFuncSeparate(NVGcontext* ctx, int srcRGB, int dstRGB, int srcAlpha, int dstAlpha);
void nvgRGBWrapper(unsigned char r, unsigned char g, unsigned char b, NVGcolor*);
void nvgRGBfWrapper(float r, float g, float b, NVGcolor*);
void nvgRGBAWrapper(unsigned char r, unsigned char g, unsigned char b, unsigned char a, NVGcolor*);
void nvgRGBAfWrapper(float r, float g, float b, float a, NVGcolor*);
void nvgLerpRGBAWrapper(NVGcolor c0, NVGcolor c1, float u, NVGcolor*);
void nvgTransRGBAWrapper(NVGcolor c0, unsigned char a, NVGcolor*);
void nvgTransRGBAfWrapper(NVGcolor c0, float a, NVGcolor*);
void nvgHSLWrapper(float h, float s, float l, NVGcolor*);
void nvgHSLAWrapper(float h, float s, float l, unsigned char a, NVGcolor*);
void nvgSave(NVGcontext* ctx);
void nvgRestore(NVGcontext* ctx);
void nvgReset(NVGcontext* ctx);
void nvgShapeAntiAlias(NVGcontext* ctx, int enabled);
void nvgStrokeColor(NVGcontext* ctx, NVGcolor color);
void nvgStrokePaint(NVGcontext* ctx, NVGpaint paint);
void nvgFillColor(NVGcontext* ctx, NVGcolor color);
void nvgFillPaint(NVGcontext* ctx, NVGpaint paint);
void nvgMiterLimit(NVGcontext* ctx, float limit);
void nvgStrokeWidth(NVGcontext* ctx, float size);
void nvgLineCap(NVGcontext* ctx, int cap);
void nvgLineJoin(NVGcontext* ctx, int join);
void nvgGlobalAlpha(NVGcontext* ctx, float alpha);
void nvgResetTransform(NVGcontext* ctx);
void nvgTransform(NVGcontext* ctx, float a, float b, float c, float d, float e, float f);
void nvgTranslate(NVGcontext* ctx, float x, float y);
void nvgRotate(NVGcontext* ctx, float angle);
void nvgSkewX(NVGcontext* ctx, float angle);
void nvgSkewY(NVGcontext* ctx, float angle);
void nvgScale(NVGcontext* ctx, float x, float y);
void nvgCurrentTransform(NVGcontext* ctx, float* xform);
void nvgTransformIdentity(float* dst);
void nvgTransformTranslate(float* dst, float tx, float ty);
void nvgTransformScale(float* dst, float sx, float sy);
void nvgTransformRotate(float* dst, float a);
void nvgTransformSkewX(float* dst, float a);
void nvgTransformSkewY(float* dst, float a);
void nvgTransformMultiply(float* dst, const float* src);
void nvgTransformPremultiply(float* dst, const float* src);
int nvgTransformInverse(float* dst, const float* src);
void nvgTransformPoint(float* dstx, float* dsty, const float* xform, float srcx, float srcy);
float nvgDegToRad(float deg);
float nvgRadToDeg(float rad);
int nvgCreateImageRGBA(NVGcontext* ctx, int w, int h, int imageFlags, const unsigned char* data);
void nvgUpdateImage(NVGcontext* ctx, int image, const unsigned char* data);
void nvgImageSize(NVGcontext* ctx, int image, int* w, int* h);
void nvgDeleteImage(NVGcontext* ctx, int image);
void nvgLinearGradientWrapper(NVGcontext* ctx, float sx, float sy, float ex, float ey, NVGcolor icol, NVGcolor ocol, NVGpaint*);
void nvgBoxGradientWrapper(NVGcontext* ctx, float x, float y, float w, float h, float r, float f, NVGcolor icol, NVGcolor ocol, NVGpaint*);
void nvgRadialGradientWrapper(NVGcontext* ctx, float cx, float cy, float inr, float outr, NVGcolor icol, NVGcolor ocol, NVGpaint*);
void nvgImagePatternWrapper(NVGcontext* ctx, float ox, float oy, float ex, float ey, float angle, int image, float alpha, NVGpaint*);
void nvgScissor(NVGcontext* ctx, float x, float y, float w, float h);
void nvgIntersectScissor(NVGcontext* ctx, float x, float y, float w, float h);
void nvgResetScissor(NVGcontext* ctx);
void nvgBeginPath(NVGcontext* ctx);
void nvgMoveTo(NVGcontext* ctx, float x, float y);
void nvgLineTo(NVGcontext* ctx, float x, float y);
void nvgBezierTo(NVGcontext* ctx, float c1x, float c1y, float c2x, float c2y, float x, float y);
void nvgQuadTo(NVGcontext* ctx, float cx, float cy, float x, float y);
void nvgArcTo(NVGcontext* ctx, float x1, float y1, float x2, float y2, float radius);
void nvgClosePath(NVGcontext* ctx);
void nvgPathWinding(NVGcontext* ctx, int dir);
void nvgArc(NVGcontext* ctx, float cx, float cy, float r, float a0, float a1, int dir);
void nvgRect(NVGcontext* ctx, float x, float y, float w, float h);
void nvgRoundedRect(NVGcontext* ctx, float x, float y, float w, float h, float r);
void nvgRoundedRectVarying(NVGcontext* ctx, float x, float y, float w, float h, float radTopLeft, float radTopRight, float radBottomRight, float radBottomLeft);
void nvgEllipse(NVGcontext* ctx, float cx, float cy, float rx, float ry);
void nvgCircle(NVGcontext* ctx, float cx, float cy, float r);
void nvgFill(NVGcontext* ctx);
void nvgStroke(NVGcontext* ctx);
int nvgCreateFont(NVGcontext* ctx, const char* name, const char* filename);
int nvgCreateFontAtIndex(NVGcontext* ctx, const char* name, const char* filename, const int fontIndex);
int nvgCreateFontMem(NVGcontext* ctx, const char* name, unsigned char* data, int ndata, int freeData);
int nvgCreateFontMemAtIndex(NVGcontext* ctx, const char* name, unsigned char* data, int ndata, int freeData, const int fontIndex);
int nvgFindFont(NVGcontext* ctx, const char* name);
int nvgAddFallbackFontId(NVGcontext* ctx, int baseFont, int fallbackFont);
int nvgAddFallbackFont(NVGcontext* ctx, const char* baseFont, const char* fallbackFont);
void nvgResetFallbackFontsId(NVGcontext* ctx, int baseFont);
void nvgResetFallbackFonts(NVGcontext* ctx, const char* baseFont);
void nvgFontSize(NVGcontext* ctx, float size);
void nvgFontBlur(NVGcontext* ctx, float blur);
void nvgTextLetterSpacing(NVGcontext* ctx, float spacing);
void nvgTextLineHeight(NVGcontext* ctx, float lineHeight);
void nvgTextAlign(NVGcontext* ctx, int align);
void nvgFontFaceId(NVGcontext* ctx, int font);
void nvgFontFace(NVGcontext* ctx, const char* font);
float nvgText(NVGcontext* ctx, float x, float y, const char* string, const char* end);
void nvgTextBox(NVGcontext* ctx, float x, float y, float breakRowWidth, const char* string, const char* end);
float nvgTextBounds(NVGcontext* ctx, float x, float y, const char* string, const char* end, float* bounds);
void nvgTextBoxBounds(NVGcontext* ctx, float x, float y, float breakRowWidth, const char* string, const char* end, float* bounds);
int nvgTextGlyphPositions(NVGcontext* ctx, float x, float y, const char* string, const char* end, NVGglyphPosition* positions, int maxPositions);
void nvgTextMetrics(NVGcontext* ctx, float* ascender, float* descender, float* lineh);
int nvgTextBreakLines(NVGcontext* ctx, const char* string, const char* end, float breakRowWidth, NVGtextRow* rows, int maxRows);

void guiDrawBezierArrow(void* gui, float width, ImVec2 p1, ImVec2 c1, ImVec2 c2, ImVec2 p2, NVGcolor innerColor, NVGcolor outerColor);
]]

-- )EOF"
