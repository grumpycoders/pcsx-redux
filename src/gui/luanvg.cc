/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include "gui/luanvg.h"

#include "gui/gui.h"
#include "lua/luawrapper.h"
#include "nanovg/src/nanovg.h"

namespace {

void guiDrawBezierArrow(PCSX::GUI* gui, float width, ImVec2 p1, ImVec2 c1, ImVec2 c2, ImVec2 p2, ImVec4 innerColor,
                        ImVec4 outerColor) {
    gui->drawBezierArrow(width, p1, c1, c2, p2, innerColor, outerColor);
}

void nvgRGBWrapper(unsigned char r, unsigned char g, unsigned char b, NVGcolor* ret) { *ret = nvgRGB(r, g, b); }
void nvgRGBfWrapper(float r, float g, float b, NVGcolor* ret) { *ret = nvgRGBf(r, g, b); }
void nvgRGBAWrapper(unsigned char r, unsigned char g, unsigned char b, unsigned char a, NVGcolor* ret) {
    *ret = nvgRGBA(r, g, b, a);
}
void nvgRGBAfWrapper(float r, float g, float b, float a, NVGcolor* ret) { *ret = nvgRGBAf(r, g, b, a); }
void nvgLerpRGBAWrapper(NVGcolor c0, NVGcolor c1, float u, NVGcolor* ret) { *ret = nvgLerpRGBA(c0, c1, u); }
void nvgTransRGBAWrapper(NVGcolor c0, unsigned char a, NVGcolor* ret) { *ret = nvgTransRGBA(c0, a); }
void nvgTransRGBAfWrapper(NVGcolor c0, float a, NVGcolor* ret) { *ret = nvgTransRGBAf(c0, a); }
void nvgHSLWrapper(float h, float s, float l, NVGcolor* ret) { *ret = nvgHSL(h, s, l); }
void nvgHSLAWrapper(float h, float s, float l, unsigned char a, NVGcolor* ret) { *ret = nvgHSLA(h, s, l, a); }

void nvgLinearGradientWrapper(NVGcontext* ctx, float sx, float sy, float ex, float ey, NVGcolor icol, NVGcolor ocol,
                              NVGpaint* ret) {
    *ret = nvgLinearGradient(ctx, sx, sy, ex, ey, icol, ocol);
}
void nvgBoxGradientWrapper(NVGcontext* ctx, float x, float y, float w, float h, float r, float f, NVGcolor icol,
                           NVGcolor ocol, NVGpaint* ret) {
    *ret = nvgBoxGradient(ctx, x, y, w, h, r, f, icol, ocol);
}
void nvgRadialGradientWrapper(NVGcontext* ctx, float cx, float cy, float inr, float outr, NVGcolor icol, NVGcolor ocol,
                              NVGpaint* ret) {
    *ret = nvgRadialGradient(ctx, cx, cy, inr, outr, icol, ocol);
}
void nvgImagePatternWrapper(NVGcontext* ctx, float ox, float oy, float ex, float ey, float angle, int image,
                            float alpha, NVGpaint* ret) {
    *ret = nvgImagePattern(ctx, ox, oy, ex, ey, angle, image, alpha);
}

template <typename T, size_t S>
void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("NANOVG");
    L.newtable();

    REGISTER(L, nvgGlobalCompositeOperation);
    REGISTER(L, nvgGlobalCompositeBlendFunc);
    REGISTER(L, nvgGlobalCompositeBlendFuncSeparate);
    REGISTER(L, nvgRGBWrapper);
    REGISTER(L, nvgRGBfWrapper);
    REGISTER(L, nvgRGBAWrapper);
    REGISTER(L, nvgRGBAfWrapper);
    REGISTER(L, nvgLerpRGBAWrapper);
    REGISTER(L, nvgTransRGBAWrapper);
    REGISTER(L, nvgTransRGBAfWrapper);
    REGISTER(L, nvgHSLWrapper);
    REGISTER(L, nvgHSLAWrapper);
    REGISTER(L, nvgSave);
    REGISTER(L, nvgRestore);
    REGISTER(L, nvgReset);
    REGISTER(L, nvgShapeAntiAlias);
    REGISTER(L, nvgStrokeColor);
    REGISTER(L, nvgStrokePaint);
    REGISTER(L, nvgFillColor);
    REGISTER(L, nvgFillPaint);
    REGISTER(L, nvgMiterLimit);
    REGISTER(L, nvgStrokeWidth);
    REGISTER(L, nvgLineCap);
    REGISTER(L, nvgLineJoin);
    REGISTER(L, nvgGlobalAlpha);
    REGISTER(L, nvgResetTransform);
    REGISTER(L, nvgTransform);
    REGISTER(L, nvgTranslate);
    REGISTER(L, nvgRotate);
    REGISTER(L, nvgSkewX);
    REGISTER(L, nvgSkewY);
    REGISTER(L, nvgScale);
    REGISTER(L, nvgCurrentTransform);
    REGISTER(L, nvgTransformIdentity);
    REGISTER(L, nvgTransformTranslate);
    REGISTER(L, nvgTransformScale);
    REGISTER(L, nvgTransformRotate);
    REGISTER(L, nvgTransformSkewX);
    REGISTER(L, nvgTransformSkewY);
    REGISTER(L, nvgTransformMultiply);
    REGISTER(L, nvgTransformPremultiply);
    REGISTER(L, nvgTransformInverse);
    REGISTER(L, nvgTransformPoint);
    REGISTER(L, nvgDegToRad);
    REGISTER(L, nvgRadToDeg);
    REGISTER(L, nvgCreateImageRGBA);
    REGISTER(L, nvgUpdateImage);
    REGISTER(L, nvgImageSize);
    REGISTER(L, nvgDeleteImage);
    REGISTER(L, nvgLinearGradientWrapper);
    REGISTER(L, nvgBoxGradientWrapper);
    REGISTER(L, nvgRadialGradientWrapper);
    REGISTER(L, nvgImagePatternWrapper);
    REGISTER(L, nvgScissor);
    REGISTER(L, nvgIntersectScissor);
    REGISTER(L, nvgResetScissor);
    REGISTER(L, nvgBeginPath);
    REGISTER(L, nvgMoveTo);
    REGISTER(L, nvgLineTo);
    REGISTER(L, nvgBezierTo);
    REGISTER(L, nvgQuadTo);
    REGISTER(L, nvgArcTo);
    REGISTER(L, nvgClosePath);
    REGISTER(L, nvgPathWinding);
    REGISTER(L, nvgArc);
    REGISTER(L, nvgRect);
    REGISTER(L, nvgRoundedRect);
    REGISTER(L, nvgRoundedRectVarying);
    REGISTER(L, nvgEllipse);
    REGISTER(L, nvgCircle);
    REGISTER(L, nvgFill);
    REGISTER(L, nvgStroke);
    REGISTER(L, nvgCreateFont);
    REGISTER(L, nvgCreateFontAtIndex);
    REGISTER(L, nvgCreateFontMem);
    REGISTER(L, nvgCreateFontMemAtIndex);
    REGISTER(L, nvgFindFont);
    REGISTER(L, nvgAddFallbackFontId);
    REGISTER(L, nvgAddFallbackFont);
    REGISTER(L, nvgResetFallbackFontsId);
    REGISTER(L, nvgResetFallbackFonts);
    REGISTER(L, nvgFontSize);
    REGISTER(L, nvgFontBlur);
    REGISTER(L, nvgTextLetterSpacing);
    REGISTER(L, nvgTextLineHeight);
    REGISTER(L, nvgTextAlign);
    REGISTER(L, nvgFontFaceId);
    REGISTER(L, nvgFontFace);
    REGISTER(L, nvgText);
    REGISTER(L, nvgTextBox);
    REGISTER(L, nvgTextBounds);
    REGISTER(L, nvgTextBoxBounds);
    REGISTER(L, nvgTextGlyphPositions);
    REGISTER(L, nvgTextMetrics);
    REGISTER(L, nvgTextBreakLines);

    REGISTER(L, guiDrawBezierArrow);

    L.settable();
    L.pop();
}

}  // namespace

void PCSX::LuaFFI::open_nvg(Lua L) {
    registerAllSymbols(L);
    static int lualoader = 2;
    static const char* nvg_cdefs = (
#include "gui/nvgffi-cdefs.lua"
    );
    static const char* nvg = (
#include "gui/nvgffi.lua"
    );
    L.load(nvg_cdefs, "internal:gui/nvgffi-cdefs.lua");
    L.load(nvg, "internal:gui/nvgffi.lua");
}
