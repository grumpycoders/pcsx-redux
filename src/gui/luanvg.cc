/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
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
#include "imgui/imgui.h"
#include "lua/luawrapper.h"
#include "nanovg/src/nanovg.h"

namespace {

void guiDrawBezierArrow(PCSX::GUI* gui, float width, float startX, float startY, float c1X, float c1Y, float c2X,
                        float c2Y, float endX, float endY, ImVec4 innerColor, ImVec4 outerColor) {
    gui->drawBezierArrow(width, {startX, startY}, {c1X, c1Y}, {c2X, c2Y}, {endX, endY}, innerColor, outerColor);
}

unsigned imguiGetViewportId() { return ImGui::GetWindowViewport()->ID; }

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
    REGISTER(L, nvgRGB);
    REGISTER(L, nvgRGBf);
    REGISTER(L, nvgRGBA);
    REGISTER(L, nvgRGBAf);
    REGISTER(L, nvgLerpRGBA);
    REGISTER(L, nvgTransRGBA);
    REGISTER(L, nvgTransRGBAf);
    REGISTER(L, nvgHSL);
    REGISTER(L, nvgHSLA);
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
    REGISTER(L, nvgLinearGradient);
    REGISTER(L, nvgBoxGradient);
    REGISTER(L, nvgRadialGradient);
    REGISTER(L, nvgImagePattern);
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
    REGISTER(L, imguiGetViewportId);

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
