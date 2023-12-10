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
    Winding = { CCW = 1, CW = 2 },
    Solidity = { SOLID = 1, HOLE = 2 },
    LineCap = { BUTT = 0, ROUND = 1, SQUARE = 2, BEVEL = 3, MITER = 4 },
    Align = { LEFT = 1, CENTER = 2, RIGHT = 4, TOP = 8, MIDDLE = 16, BOTTOM = 32, BASELINE = 64 },
    BlendFactor = {
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
    CompositeOperation = {
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
    ImageFlags = { GENERATE_MIPMAPS = 1, REPEATX = 2, REPEATY = 4, FLIPY = 8, PREMULTIPLIED = 16 },
    Color = {
        New = function(r, g, b, a)
            local c = ffi.new('NVGcolor')
            c.r = r or 0.0
            c.g = g or 0.0
            c.b = b or 0.0
            c.a = a or 1.0
            return c
        end,
    },
    Paint = { New = function() return ffi.new('NVGpaint') end },
    globalCompositeOperation = function(self, op) C.nvgGlobalCompositeOperation(self._ctx, op) end,
    globalCompositeBlendFunc = function(self, sfactor, dfactor)
        C.nvgGlobalCompositeBlendFunc(self._ctx, sfactor, dfactor)
    end,
    globalCompositeBlendFuncSeparate = function(self, srcRGB, dstRGB, srcAlpha, dstAlpha)
        C.nvgGlobalCompositeBlendFuncSeparate(self._ctx, srcRGB, dstRGB, srcAlpha, dstAlpha)
    end,
    RGB = function(r, g, b)
        ret = ffi.new('NVGcolor[1]')
        C.nvgRGBWrapper(r, g, b, ret)
        return ret[0]
    end,
    RGBf = function(r, g, b)
        ret = ffi.new('NVGcolor[1]')
        C.nvgRGBfWrapper(r, g, b, ret)
        return ret[0]
    end,
    RGBA = function(r, g, b, a)
        ret = ffi.new('NVGcolor[1]')
        C.nvgRGBAWrapper(r, g, b, a, ret)
        return ret[0]
    end,
    RGBAf = function(r, g, b, a)
        ret = ffi.new('NVGcolor[1]')
        C.nvgRGBAfWrapper(r, g, b, a, ret)
        return ret[0]
    end,
    lerpRGBA = function(c0, c1, u)
        ret = ffi.new('NVGcolor[1]')
        C.nvgLerpRGBAWrapper(c0, c1, u, ret)
        return ret[0]
    end,
    transRGBA = function(c0, a)
        ret = ffi.new('NVGcolor[1]')
        C.nvgTransRGBAWrapper(c0, a, ret)
        return ret[0]
    end,
    transRGBAf = function(c0, a)
        ret = ffi.new('NVGcolor[1]')
        C.nvgTransRGBAfWrapper(c0, a, ret)
        return ret[0]
    end,
    HSL = function(h, s, l)
        ret = ffi.new('NVGcolor[1]')
        C.nvgHSLWrapper(h, s, l, ret)
        return ret[0]
    end,
    HSLA = function(h, s, l, a)
        ret = ffi.new('NVGcolor[1]')
        C.nvgHSLAWrapper(h, s, l, a, ret)
        return ret[0]
    end,
    save = function(self) C.nvgSave(self._ctx) end,
    restore = function(self) C.nvgRestore(self._ctx) end,
    reset = function(self) C.nvgReset(self._ctx) end,
    shapeAntiAlias = function(self, enabled) C.nvgShapeAntiAlias(self._ctx, enabled and 1 or 0) end,
    strokeColor = function(self, color) C.nvgStrokeColor(self._ctx, color) end,
    strokePaint = function(self, paint) C.nvgStrokePaint(self._ctx, paint) end,
    fillColor = function(self, color) C.nvgFillColor(self._ctx, color) end,
    fillPaint = function(self, paint) C.nvgFillPaint(self._ctx, paint) end,
    miterLimit = function(self, limit) C.nvgMiterLimit(self._ctx, limit) end,
    strokeWidth = function(self, size) C.nvgStrokeWidth(self._ctx, size) end,
    lineCap = function(self, cap) C.nvgLineCap(self._ctx, cap) end,
    lineJoin = function(self, join) C.nvgLineJoin(self._ctx, join) end,
    globalAlpha = function(self, alpha) C.nvgGlobalAlpha(self._ctx, alpha) end,
    resetTransform = function(self) C.nvgResetTransform(self._ctx) end,
    translate = function(self, x, y) C.nvgTranslate(self._ctx, x, y) end,
    rotate = function(self, angle) C.nvgRotate(self._ctx, angle) end,
    skewX = function(self, angle) C.nvgSkewX(self._ctx, angle) end,
    skewY = function(self, angle) C.nvgSkewY(self._ctx, angle) end,
    scale = function(self, x, y) C.nvgScale(self._ctx, x, y) end,
    currentTransform = function(self, xform) C.nvgCurrentTransform(self._ctx, xform) end,
    transFormIdentity = C.nvgTransformIdentity,
    transformTranslate = C.nvgTransformTranslate,
    transformScale = C.nvgTransformScale,
    transformRotate = C.nvgTransformRotate,
    transformSkewX = C.nvgTransformSkewX,
    transformSkewY = C.nvgTransformSkewY,
    transformMultiply = C.nvgTransformMultiply,
    transformPremultiply = C.nvgTransformPremultiply,
    transformInverse = C.nvgTransformInverse,
    transformPoint = C.nvgTransformPoint,
    degToRad = C.nvgDegToRad,
    radToDeg = C.nvgRadToDeg,
    createImageRGBA = function(self, w, h, imageFlags, data)
        return C.nvgCreateImageRGBA(self._ctx, w, h, imageFlags, data)
    end,
    updateImage = function(self, image, data) C.nvgUpdateImage(self._ctx, image, data) end,
    imageSize = function(self, image, w, h) C.nvgImageSize(self._ctx, image, w, h) end,
    deleteImage = function(self, image) C.nvgDeleteImage(self._ctx, image) end,
    linearGradient = function(self, sx, sy, ex, ey, icol, ocol)
        local ret = ffi.new('NVGpaint[1]')
        C.nvgLinearGradientWrapper(self._ctx, sx, sy, ex, ey, icol, ocol, ret)
        return ret[0]
    end,
    boxGradient = function(self, x, y, w, h, r, f, icol, ocol)
        local ret = ffi.new('NVGpaint[1]')
        C.nvgBoxGradientWrapper(self._ctx, x, y, w, h, r, f, icol, ocol, ret)
        return ret[0]
    end,
    radialGradient = function(self, cx, cy, inr, outr, icol, ocol)
        local ret = ffi.new('NVGpaint[1]')
        C.nvgRadialGradientWrapper(self._ctx, cx, cy, inr, outr, icol, ocol, ret)
        return ret[0]
    end,
    imagePattern = function(self, ox, oy, ex, ey, angle, image, alpha)
        local ret = ffi.new('NVGpaint[1]')
        C.nvgImagePatternWrapper(self._ctx, ox, oy, ex, ey, angle, image, alpha, ret)
        return ret[0]
    end,
    scissor = function(self, x, y, w, h) C.nvgScissor(self._ctx, x, y, w, h) end,
    intersectScissor = function(self, x, y, w, h) C.nvgIntersectScissor(self._ctx, x, y, w, h) end,
    resetScissor = function(self) C.nvgResetScissor(self._ctx) end,
    beginPath = function(self) C.nvgBeginPath(self._ctx) end,
    moveTo = function(self, x, y) C.nvgMoveTo(self._ctx, x, y) end,
    lineTo = function(self, x, y) C.nvgLineTo(self._ctx, x, y) end,
    bezierTo = function(self, c1x, c1y, c2x, c2y, x, y) C.nvgBezierTo(self._ctx, c1x, c1y, c2x, c2y, x, y) end,
    quadTo = function(self, cx, cy, x, y) C.nvgQuadTo(self._ctx, cx, cy, x, y) end,
    arcTo = function(self, x1, y1, x2, y2, radius) C.nvgArcTo(self._ctx, x1, y1, x2, y2, radius) end,
    closePath = function(self) C.nvgClosePath(self._ctx) end,
    pathWinding = function(self, dir) C.nvgPathWinding(self._ctx, dir) end,
    arc = function(self, cx, cy, r, a0, a1, dir) C.nvgArc(self._ctx, cx, cy, r, a0, a1, dir) end,
    rect = function(self, x, y, w, h) C.nvgRect(self._ctx, x, y, w, h) end,
    roundedRect = function(self, x, y, w, h, r) C.nvgRoundedRect(self._ctx, x, y, w, h, r) end,
    roundedRectVarying = function(self, x, y, w, h, radTopLeft, radTopRight, radBottomRight, radBottomLeft)
        C.nvgRoundedRectVarying(self._ctx, x, y, w, h, radTopLeft, radTopRight, radBottomRight, radBottomLeft)
    end,
    ellipse = function(self, cx, cy, rx, ry) C.nvgEllipse(self._ctx, cx, cy, rx, ry) end,
    circle = function(self, cx, cy, r) C.nvgCircle(self._ctx, cx, cy, r) end,
    fill = function(self) C.nvgFill(self._ctx) end,
    stroke = function(self) C.nvgStroke(self._ctx) end,
    createFont = function(self, name, filename) return C.nvgCreateFont(self._ctx, name, filename) end,
    createFontAtIndex = function(self, name, filename, fontIndex)
        return C.nvgCreateFontAtIndex(self._ctx, name, filename, fontIndex)
    end,
    createFontMem = function(self, name, data, ndata, freeData)
        return C.nvgCreateFontMem(self._ctx, name, data, ndata, freeData)
    end,
    createFontMemAtIndex = function(self, name, data, ndata, freeData, fontIndex)
        return C.nvgCreateFontMemAtIndex(self._ctx, name, data, ndata, freeData, fontIndex)
    end,
    findFont = function(self, name) return C.nvgFindFont(self._ctx, name) end,
    addFallbackFontId = function(self, baseFont, fallbackFont)
        C.nvgAddFallbackFontId(self._ctx, baseFont, fallbackFont)
    end,
    addFallbackFont = function(self, baseFont, fallbackFont) C.nvgAddFallbackFont(self._ctx, baseFont, fallbackFont) end,
    resetFallbackFontsId = function(self, baseFont) C.nvgResetFallbackFontsId(self._ctx, baseFont) end,
    resetFallbackFonts = function(self, baseFont) C.nvgResetFallbackFonts(self._ctx, baseFont) end,
    fontSize = function(self, size) C.nvgFontSize(self._ctx, size) end,
    fontBlur = function(self, blur) C.nvgFontBlur(self._ctx, blur) end,
    textLetterSpacing = function(self, spacing) C.nvgTextLetterSpacing(self._ctx, spacing) end,
    textLineHeight = function(self, lineHeight) C.nvgTextLineHeight(self._ctx, lineHeight) end,
    textAlign = function(self, align) C.nvgTextAlign(self._ctx, align) end,
    fontFaceId = function(self, font) C.nvgFontFaceId(self._ctx, font) end,
    fontFace = function(self, font) C.nvgFontFace(self._ctx, font) end,
    text = function(self, x, y, string) C.nvgText(self._ctx, x, y, string, nil) end,
    textBox = function(self, x, y, breakRowWidth, string) C.nvgTextBox(self._ctx, x, y, breakRowWidth, string, nil) end,
    textBounds = function(self, x, y, string)
        local bounds = ffi.new('float[4]')
        local ret = C.nvgTextBounds(self._ctx, x, y, string, nil, bounds)
        return ret, bounds
    end,
    textBoxBounds = function(self, x, y, breakRowWidth, string)
        local bounds = ffi.new('float[4]')
        C.nvgTextBoxBounds(self._ctx, x, y, breakRowWidth, string, nil, bounds)
        return bounds
    end,
    textGlyphPositions = function(self, x, y, string)
        local positions = ffi.new('NVGglyphPosition[?]', #string)
        local ret = C.nvgTextGlyphPositions(self._ctx, x, y, string, nil, positions, #string)
        return ret, positions
    end,
    textMetrics = function(self)
        local ascender = ffi.new('float[1]')
        local descender = ffi.new('float[1]')
        local lineh = ffi.new('float[1]')
        C.nvgTextMetrics(self._ctx, ascender, descender, lineh)
        return ascender[0], descender[0], lineh[0]
    end,
    textBreakLines = function(self, string, breakRowWidth)
        local rows = ffi.new('NVGtextRow[?]', #string)
        local ret = C.nvgTextBreakLines(self._ctx, string, nil, breakRowWidth, rows, #string)
        return ret, rows
    end,
    drawBezierArrow = function(self, width, p1, c1, c2, p2, innerColor, outerColor)
        if innerColor == nil then innerColor = self.Color.New(1.0, 1.0, 1.0) end
        if outerColor == nil then outerColor = self.Color.New(0.5, 0.5, 0.5) end
        local p1 = imgui.extra.ImVec2.New(p1.x, p1.y)
        local c1 = imgui.extra.ImVec2.New(c1.x, c1.y)
        local c2 = imgui.extra.ImVec2.New(c2.x, c2.y)
        local p2 = imgui.extra.ImVec2.New(p2.x, p2.y)
        C.nvgDrawBezierArrow(self._gui, width, p1, c1, c2, p2, innerColor, outerColor)
    end,

    queueNvgRender = function(self, func)
        local viewportId = imgui.extra.getCurrentViewportId()
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
        if viewportQueue == nil then return end
        for i = 1, #viewportQueue do viewportQueue[i]() end
        self._queue[viewportId] = nil
    end,
}

-- )EOF"
