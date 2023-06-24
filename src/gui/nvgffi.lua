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

local C = ffi.load 'NANOVG'

nvg = {
    winding = {
        CCW = 1,
        CW = 2,
    },
    solidity = {
        SOLID = 1,
        HOLE = 2,
    },
    lineCap = {
        BUTT = 0,
        ROUND = 1,
        SQUARE = 2,
        BEVEL = 3,
        MITER = 4,
    },
    align = {
        LEFT = 1,
        CENTER = 2,
        RIGHT = 4,
        TOP = 8,
        MIDDLE = 16,
        BOTTOM = 32,
        BASELINE = 64,
    },
    blendFactor = {
        ZERO = 1,
        ONE = 2,
        SRC_COLOR = 4,
        ONE_MINUS_SRC_COLOR = 8,
        DST_COLOR = 16,
        ONE_MINUS_DST_COLOR = 32,
        SRC_ALPHA = 64,
        ONE_MINUS_SRC_ALPHA = 128,
        DST_ALPHA = 256,
        ONE_MINUS_DST_ALPHA = 512,
        SRC_ALPHA_SATURATE = 1024,
    },
    compositeOperation = {
        SOURCE_OVER = 0,
        SOURCE_IN = 1,
        SOURCE_OUT = 2,
        ATOP = 3,
        DESTINATION_OVER = 4,
        DESTINATION_IN = 5,
        DESTINATION_OUT = 6,
        DESTINATION_ATOP = 7,
        LIGHTER = 8,
        COPY = 9,
        XOR = 10,
    },
    imageFlags = {
        GENERATE_MIPMAPS = 1,
        REPEATX = 2,
        REPEATY = 4,
        FLIPY = 8,
        PREMULTIPLIED = 16,
    },
    Color = {
        New = function(r, g, b, a)
            local c = ffi.new('NVGcolor')
            c.r = r or 0
            c.g = g or 0
            c.b = b or 0
            c.a = a or 0
            return c
        end,
    },
    Paint = {
        New = function()
            return ffi.new('NVGpaint')
        end,
    },
    GlobalCompositeOperation = function(self, op)
        C.nvgGlobalCompositeOperation(self.ctx, op)
    end,
    GlobalCompositeBlendFunc = function(self, sfactor, dfactor)
        C.nvgGlobalCompositeBlendFunc(self.ctx, sfactor, dfactor)
    end,
    GlobalCompositeBlendFuncSeparate = function(self, srcRGB, dstRGB, srcAlpha, dstAlpha)
        C.nvgGlobalCompositeBlendFuncSeparate(self.ctx, srcRGB, dstRGB, srcAlpha, dstAlpha)
    end,
    RGB = C.nvgRGB,
    RGBf = C.nvgRGBf,
    RGBA = C.nvgRGBA,
    RGBAf = C.nvgRGBAf,
    LerpRGBA = C.nvgLerpRGBA,
    TransRGBA = C.nvgTransRGBA,
    TransRGBAf = C.nvgTransRGBAf,
    HSL = C.nvgHSL,
    HSLA = C.nvgHSLA,
    Save = function(self)
        C.nvgSave(self.ctx)
    end,
    Restore = function(self)
        C.nvgRestore(self.ctx)
    end,
    Reset = function(self)
        C.nvgReset(self.ctx)
    end,
    ShapeAntiAlias = function(self, enabled)
        C.nvgShapeAntiAlias(self.ctx, enabled and 1 or 0)
    end,
    StrokeColor = function(self, color)
        C.nvgStrokeColor(self.ctx, color)
    end,
    StrokePaint = function(self, paint)
        C.nvgStrokePaint(self.ctx, paint)
    end,
    FillColor = function(self, color)
        C.nvgFillColor(self.ctx, color)
    end,
    FillPaint = function(self, paint)
        C.nvgFillPaint(self.ctx, paint)
    end,
    MiterLimit = function(self, limit)
        C.nvgMiterLimit(self.ctx, limit)
    end,
    StrokeWidth = function(self, size)
        C.nvgStrokeWidth(self.ctx, size)
    end,
    LineCap = function(self, cap)
        C.nvgLineCap(self.ctx, cap)
    end,
    LineJoin = function(self, join)
        C.nvgLineJoin(self.ctx, join)
    end,
    GlobalAlpha = function(self, alpha)
        C.nvgGlobalAlpha(self.ctx, alpha)
    end,
    ResetTransform = function(self)
        C.nvgResetTransform(self.ctx)
    end,
    Translate = function(self, x, y)
        C.nvgTranslate(self.ctx, x, y)
    end,
    Rotate = function(self, angle)
        C.nvgRotate(self.ctx, angle)
    end,
    SkewX = function(self, angle)
        C.nvgSkewX(self.ctx, angle)
    end,
    SkewY = function(self, angle)
        C.nvgSkewY(self.ctx, angle)
    end,
    Scale = function(self, x, y)
        C.nvgScale(self.ctx, x, y)
    end,
    CurrentTransform = function(self, xform)
        C.nvgCurrentTransform(self.ctx, xform)
    end,
    TransFormIdentity = C.nvgTransformIdentity,
    TransformTranslate = C.nvgTransformTranslate,
    TransformScale = C.nvgTransformScale,
    TransformRotate = C.nvgTransformRotate,
    TransformSkewX = C.nvgTransformSkewX,
    TransformSkewY = C.nvgTransformSkewY,
    TransformMultiply = C.nvgTransformMultiply,
    TransformPremultiply = C.nvgTransformPremultiply,
    TransformInverse = C.nvgTransformInverse,
    TransformPoint = C.nvgTransformPoint,
    DegToRad = C.nvgDegToRad,
    RadToDeg = C.nvgRadToDeg,
    CreateImageRGBA = function(self, w, h, imageFlags, data)
        return C.nvgCreateImageRGBA(self.ctx, w, h, imageFlags, data)
    end,
    UpdateImage = function(self, image, data)
        C.nvgUpdateImage(self.ctx, image, data)
    end,
    ImageSize = function(self, image, w, h)
        C.nvgImageSize(self.ctx, image, w, h)
    end,
    DeleteImage = function(self, image)
        C.nvgDeleteImage(self.ctx, image)
    end,
    LinearGradient = function(self, sx, sy, ex, ey, icol, ocol)
        return C.nvgLinearGradient(self.ctx, sx, sy, ex, ey, icol, ocol)
    end,
    BoxGradient = function(self, x, y, w, h, r, f, icol, ocol)
        return C.nvgBoxGradient(self.ctx, x, y, w, h, r, f, icol, ocol)
    end,
    RadialGradient = function(self, cx, cy, inr, outr, icol, ocol)
        return C.nvgRadialGradient(self.ctx, cx, cy, inr, outr, icol, ocol)
    end,
    ImagePattern = function(self, ox, oy, ex, ey, angle, image, alpha)
        return C.nvgImagePattern(self.ctx, ox, oy, ex, ey, angle, image, alpha)
    end,
    Scissor = function(self, x, y, w, h)
        C.nvgScissor(self.ctx, x, y, w, h)
    end,
    IntersectScissor = function(self, x, y, w, h)
        C.nvgIntersectScissor(self.ctx, x, y, w, h)
    end,
    ResetScissor = function(self)
        C.nvgResetScissor(self.ctx)
    end,
    BeginPath = function(self)
        C.nvgBeginPath(self.ctx)
    end,
    MoveTo = function(self, x, y)
        C.nvgMoveTo(self.ctx, x, y)
    end,
    LineTo = function(self, x, y)
        C.nvgLineTo(self.ctx, x, y)
    end,
    BezierTo = function(self, c1x, c1y, c2x, c2y, x, y)
        C.nvgBezierTo(self.ctx, c1x, c1y, c2x, c2y, x, y)
    end,
    QuadTo = function(self, cx, cy, x, y)
        C.nvgQuadTo(self.ctx, cx, cy, x, y)
    end,
    ArcTo = function(self, x1, y1, x2, y2, radius)
        C.nvgArcTo(self.ctx, x1, y1, x2, y2, radius)
    end,
    ClosePath = function(self)
        C.nvgClosePath(self.ctx)
    end,
    PathWinding = function(self, dir)
        C.nvgPathWinding(self.ctx, dir)
    end,
    Arc = function(self, cx, cy, r, a0, a1, dir)
        C.nvgArc(self.ctx, cx, cy, r, a0, a1, dir)
    end,
    Rect = function(self, x, y, w, h)
        C.nvgRect(self.ctx, x, y, w, h)
    end,
    RoundedRect = function(self, x, y, w, h, r)
        C.nvgRoundedRect(self.ctx, x, y, w, h, r)
    end,
    RoundedRectVarying = function(self, x, y, w, h, radTopLeft, radTopRight, radBottomRight, radBottomLeft)
        C.nvgRoundedRectVarying(self.ctx, x, y, w, h, radTopLeft, radTopRight, radBottomRight, radBottomLeft)
    end,
    Ellipse = function(self, cx, cy, rx, ry)
        C.nvgEllipse(self.ctx, cx, cy, rx, ry)
    end,
    Circle = function(self, cx, cy, r)
        C.nvgCircle(self.ctx, cx, cy, r)
    end,
    Fill = function(self)
        C.nvgFill(self.ctx)
    end,
    Stroke = function(self)
        C.nvgStroke(self.ctx)
    end,
    CreateFont = function(self, name, filename)
        return C.nvgCreateFont(self.ctx, name, filename)
    end,
    CreateFontAtIndex = function(self, name, filename, fontIndex)
        return C.nvgCreateFontAtIndex(self.ctx, name, filename, fontIndex)
    end,
    CreateFontMem = function(self, name, data, ndata, freeData)
        return C.nvgCreateFontMem(self.ctx, name, data, ndata, freeData)
    end,
    CreateFontMemAtIndex = function(self, name, data, ndata, freeData, fontIndex)
        return C.nvgCreateFontMemAtIndex(self.ctx, name, data, ndata, freeData, fontIndex)
    end,
    FindFont = function(self, name)
        return C.nvgFindFont(self.ctx, name)
    end,
    AddFallbackFontId = function(self, baseFont, fallbackFont)
        C.nvgAddFallbackFontId(self.ctx, baseFont, fallbackFont)
    end,
    AddFallbackFont = function(self, baseFont, fallbackFont)
        C.nvgAddFallbackFont(self.ctx, baseFont, fallbackFont)
    end,
    ResetFallbackFontsId = function(self, baseFont)
        C.nvgResetFallbackFontsId(self.ctx, baseFont)
    end,
    ResetFallbackFonts = function(self, baseFont)
        C.nvgResetFallbackFonts(self.ctx, baseFont)
    end,
    FontSize = function(self, size)
        C.nvgFontSize(self.ctx, size)
    end,
    FontBlur = function(self, blur)
        C.nvgFontBlur(self.ctx, blur)
    end,
    TextLetterSpacing = function(self, spacing)
        C.nvgTextLetterSpacing(self.ctx, spacing)
    end,
    TextLineHeight = function(self, lineHeight)
        C.nvgTextLineHeight(self.ctx, lineHeight)
    end,
    TextAlign = function(self, align)
        C.nvgTextAlign(self.ctx, align)
    end,
    FontFaceId = function(self, font)
        C.nvgFontFaceId(self.ctx, font)
    end,
    FontFace = function(self, font)
        C.nvgFontFace(self.ctx, font)
    end,
    Text = function(self, x, y, string)
        C.nvgText(self.ctx, x, y, string, nil)
    end,
    TextBox = function(self, x, y, breakRowWidth, string)
        C.nvgTextBox(self.ctx, x, y, breakRowWidth, string, nil)
    end,
    TextBounds = function(self, x, y, string)
        local bounds = ffi.new("float[4]")
        local ret = C.nvgTextBounds(self.ctx, x, y, string, nil, bounds)
        return ret, bounds
    end,
    TextBoxBounds = function(self, x, y, breakRowWidth, string)
        local bounds = ffi.new("float[4]")
        C.nvgTextBoxBounds(self.ctx, x, y, breakRowWidth, string, nil, bounds)
        return bounds
    end,
    TextGlyphPositions = function(self, x, y, string)
        local positions = ffi.new("NVGglyphPosition[?]", #string)
        local ret = C.nvgTextGlyphPositions(self.ctx, x, y, string, nil, positions, #string)
        return ret, positions
    end,
    TextMetrics = function(self)
        local ascender = ffi.new("float[1]")
        local descender = ffi.new("float[1]")
        local lineh = ffi.new("float[1]")
        C.nvgTextMetrics(self.ctx, ascender, descender, lineh)
        return ascender[0], descender[0], lineh[0]
    end,
    TextBreakLines = function(self, string, breakRowWidth)
        local rows = ffi.new("NVGtextRow[?]", #string)
        local ret = C.nvgTextBreakLines(self.ctx, string, nil, breakRowWidth, rows, #string)
        return ret, rows
    end,
    DrawBezierArrow = function(self, width, startX, startY, c1X, c1Y, c2X, c2Y, endX, endY, innerColor, outerColor)
        if innerColor == nil then
            innerColor = ffi.new("NVGcolor")
            innerColor.r = 1.0
            innerColor.g = 1.0
            innerColor.b = 1.0
            innerColor.a = 1.0
        end
        if outerColor == nil then
            outerColor = ffi.new("NVGcolor")
            outerColor.r = 0.5
            outerColor.g = 0.5
            outerColor.b = 0.5
            outerColor.a = 1.0
        end
        C.nvgDrawBezierArrow(self.ctx, width, startX, startY, c1X, c1Y, c2X, c2Y, endX, endY, innerColor, outerColor)

    queueNvgRender = function(self, func)
        local viewportId = C.imguiGetViewportId()
        local viewportQueue = self._queue[viewportId]
        if viewportQueue == nil then
            viewportQueue = {}
            self._queue[viewportId] = viewportQueue
        end
        viewportQueue[#viewportQueue + 1] = func
    end,
    _queue = {},
    _processQueueForViewportId = function(self, viewportId)
        local viewportQueue = self._queue[viewportId]
        if viewportQueue == nil then
            return
        end
        for i = 1, #viewportQueue do
            viewportQueue[i]()
        end
        self._queue[viewportId] = nil
    end,
}

-- )EOF"
