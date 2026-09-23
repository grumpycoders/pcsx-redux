-- lualoader, R"EOF(--
--   Copyright (C) 2026 PCSX-Redux authors
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

local C = ffi.load 'THORVG'

local function camelCase(name)
    return (name:gsub('_(%a)', function(c) return c:upper() end))
end

-- Methods are generated from the C API, so e.g. tvg_shape_append_rect(shape, ...)
-- becomes shape:appendRect(...). They return the raw Tvg_Result, where 0 means success.
local function makeMethods(prefix, names, methods)
    methods = methods or {}
    for _, name in ipairs(names) do
        local f = C[prefix .. name]
        methods[camelCase(name)] = function(self, ...) return f(self, ...) end
    end
    return methods
end

local paintMethods = makeMethods('tvg_paint_', {
    'duplicate', 'get_aabb', 'get_clip', 'get_data', 'get_id', 'get_mask_method', 'get_obb',
    'get_opacity', 'get_parent', 'get_transform', 'get_type', 'get_visible', 'intersects',
    'intersects_region', 'rotate', 'scale', 'set_blend_method', 'set_clip', 'set_data', 'set_id',
    'set_mask_method', 'set_opacity', 'set_transform', 'set_visible', 'translate'
})

local shapeMethods = makeMethods('tvg_shape_', {
    'append_circle', 'append_path', 'append_rect', 'close', 'cubic_to', 'get_fill_color',
    'get_fill_rule', 'get_gradient', 'get_path', 'get_stroke_cap', 'get_stroke_color',
    'get_stroke_dash', 'get_stroke_gradient', 'get_stroke_join', 'get_stroke_miterlimit',
    'get_stroke_width', 'line_to', 'move_to', 'reset', 'set_fill_color', 'set_fill_rule',
    'set_paint_order', 'set_stroke_cap', 'set_stroke_color', 'set_stroke_dash', 'set_stroke_join',
    'set_stroke_miterlimit', 'set_stroke_width', 'set_trimpath'
})

local sceneMethods = makeMethods('tvg_scene_', {
    'add', 'add_effect_drop_shadow', 'add_effect_fill', 'add_effect_gaussian_blur', 'add_effect_tint',
    'add_effect_tritone', 'clear_effects', 'insert', 'remove'
})

local pictureMethods = makeMethods('tvg_picture_', {
    'get_origin', 'get_paint', 'get_size', 'load', 'load_data', 'load_raw', 'set_accessible',
    'set_asset_resolver', 'set_filter', 'set_origin', 'set_size'
})

local textMethods = makeMethods('tvg_text_', {
    'align', 'get_glyph_metrics', 'get_text', 'get_text_metrics', 'layout', 'line_count', 'set_color',
    'set_font', 'set_italic', 'set_outline', 'set_size', 'set_text', 'spacing', 'wrap_mode'
})

function shapeMethods:appendRect(x, y, w, h, rx, ry, cw)
    return C.tvg_shape_append_rect(self, x, y, w, h, rx or 0, ry or rx or 0, cw ~= false)
end
function shapeMethods:appendCircle(cx, cy, rx, ry, cw) return C.tvg_shape_append_circle(self, cx, cy, rx, ry or rx, cw ~= false) end
function shapeMethods:setFillColor(r, g, b, a) return C.tvg_shape_set_fill_color(self, r, g, b, a or 255) end
function shapeMethods:setStrokeColor(r, g, b, a) return C.tvg_shape_set_stroke_color(self, r, g, b, a or 255) end

-- Shapes and texts take ownership of the gradients given to them, so they get
-- a copy, and the Lua object stays valid and garbage collected as usual.
function shapeMethods:setGradient(gradient) return C.tvg_shape_set_gradient(self, C.tvg_gradient_duplicate(gradient)) end
function shapeMethods:setStrokeGradient(gradient)
    return C.tvg_shape_set_stroke_gradient(self, C.tvg_gradient_duplicate(gradient))
end
function textMethods:setGradient(gradient) return C.tvg_text_set_gradient(self, C.tvg_gradient_duplicate(gradient)) end

local methodsByType = {
    [C.TVG_TYPE_SHAPE] = shapeMethods,
    [C.TVG_TYPE_SCENE] = sceneMethods,
    [C.TVG_TYPE_PICTURE] = pictureMethods,
    [C.TVG_TYPE_TEXT] = textMethods,
}
for _, methods in pairs(methodsByType) do setmetatable(methods, { __index = paintMethods }) end

local paintType = ffi.new('Tvg_Type[1]')
ffi.metatype('struct _Tvg_Paint', {
    __index = function(self, key)
        C.tvg_paint_get_type(self, paintType)
        local methods = methodsByType[tonumber(paintType[0])] or paintMethods
        return methods[key]
    end,
})

local gradientMethods = makeMethods('tvg_gradient_', {
    'get_color_stops', 'get_spread', 'get_transform', 'get_type', 'set_color_stops', 'set_spread',
    'set_transform'
})
gradientMethods.setLinear = function(self, ...) return C.tvg_linear_gradient_set(self, ...) end
gradientMethods.getLinear = function(self, ...) return C.tvg_linear_gradient_get(self, ...) end
gradientMethods.setRadial = function(self, ...) return C.tvg_radial_gradient_set(self, ...) end
gradientMethods.getRadial = function(self, ...) return C.tvg_radial_gradient_get(self, ...) end
-- Accepts either a Tvg_Color_Stop array and its count, or a table of { offset, r, g, b, a } entries.
function gradientMethods:setColorStops(stops, count)
    if type(stops) == 'table' then
        count = #stops
        local array = ffi.new('Tvg_Color_Stop[?]', count)
        for i, stop in ipairs(stops) do
            array[i - 1].offset, array[i - 1].r, array[i - 1].g, array[i - 1].b, array[i - 1].a =
                stop[1], stop[2], stop[3], stop[4], stop[5] or 255
        end
        stops = array
    end
    return C.tvg_gradient_set_color_stops(self, stops, count)
end
ffi.metatype('struct _Tvg_Gradient', { __index = gradientMethods })

local animationMethods = makeMethods('tvg_animation_', {
    'get_duration', 'get_frame', 'get_picture', 'get_segment', 'get_total_frame', 'set_frame',
    'set_segment'
})
makeMethods('tvg_lottie_animation_', {
    'apply_slot', 'del_slot', 'expressions_supported', 'gen_slot', 'get_marker', 'get_marker_info',
    'get_markers_cnt', 'get_volume', 'set_audio_resolver', 'set_marker', 'set_quality', 'set_volume',
    'tween', 'tween_go', 'tween_to'
}, animationMethods)
ffi.metatype('struct _Tvg_Animation', { __index = animationMethods })

-- Lua holds one reference on the paints it creates, and releases it when collected.
-- Adding a paint to a scene takes another reference, so a paint stays alive while
-- it is displayed, even if the Lua object goes away.
local function ownPaint(paint)
    if paint == nil then return nil end
    C.tvg_paint_ref(paint)
    return ffi.gc(paint, function(p) C.tvg_paint_unref(p, true) end)
end

local function colorComponents(color, default)
    color = color or default
    return color.r or color[1], color.g or color[2], color.b or color[3], color.a or color[4] or 1.0
end

tvg = {
    C = C,
    Shape = function() return ownPaint(C.tvg_shape_new()) end,
    Scene = function() return ownPaint(C.tvg_scene_new()) end,
    Picture = function() return ownPaint(C.tvg_picture_new()) end,
    Text = function() return ownPaint(C.tvg_text_new()) end,
    LinearGradient = function(x1, y1, x2, y2)
        local gradient = ffi.gc(C.tvg_linear_gradient_new(), C.tvg_gradient_del)
        if x1 then C.tvg_linear_gradient_set(gradient, x1, y1, x2, y2) end
        return gradient
    end,
    RadialGradient = function(cx, cy, r, fx, fy, fr)
        local gradient = ffi.gc(C.tvg_radial_gradient_new(), C.tvg_gradient_del)
        if cx then C.tvg_radial_gradient_set(gradient, cx, cy, r, fx or cx, fy or cy, fr or 0) end
        return gradient
    end,
    Animation = function() return ffi.gc(C.tvg_animation_new(), C.tvg_animation_del) end,
    LottieAnimation = function() return ffi.gc(C.tvg_lottie_animation_new(), C.tvg_animation_del) end,
    loadFont = function(path) return C.tvg_font_load(path) end,
    unloadFont = function(path) return C.tvg_font_unload(path) end,

    -- The scene rendered on top of an ImGui viewport, in ImGui coordinates. Add paints
    -- to it, and remove them when they should stop being displayed. The returned object
    -- holds its own reference, so it stays valid if the viewport goes away, but it is
    -- no longer displayed then. Defaults to the viewport of the ImGui window being drawn.
    getViewportScene = function(viewportId)
        if viewportId == nil then viewportId = imgui.extra.getCurrentViewportId() end
        local scene = C.tvgReduxGetViewportScene(tvg._gui, viewportId)
        if scene == nil then return nil end
        return ownPaint(ffi.cast('Tvg_Paint', scene))
    end,

    -- Draws an arrow on top of the current ImGui viewport, for the current frame only.
    drawBezierArrow = function(width, p1, c1, c2, p2, innerColor, outerColor)
        local ir, ig, ib, ia = colorComponents(innerColor, { 1.0, 1.0, 1.0, 1.0 })
        local or_, og, ob, oa = colorComponents(outerColor, { 0.5, 0.5, 0.5, 1.0 })
        C.tvgReduxDrawBezierArrow(tvg._gui, width, imgui.extra.ImVec2.New(p1.x, p1.y),
                                  imgui.extra.ImVec2.New(c1.x, c1.y), imgui.extra.ImVec2.New(c2.x, c2.y),
                                  imgui.extra.ImVec2.New(p2.x, p2.y), ir, ig, ib, ia, or_, og, ob, oa)
    end,
}

-- )EOF"
