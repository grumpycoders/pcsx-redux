/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "gui/luatvg.h"

#include "gui/gui.h"
#include "lua/luawrapper.h"
#include "thorvg/inc/thorvg.h"
#include "thorvg/src/bindings/capi/thorvg_capi.h"

namespace {

void* tvgReduxGetViewportScene(PCSX::GUI* gui, unsigned viewportId) { return gui->getTvgViewportScene(viewportId); }

void tvgReduxDrawBezierArrow(PCSX::GUI* gui, float width, ImVec2 p1, ImVec2 c1, ImVec2 c2, ImVec2 p2, float ir,
                             float ig, float ib, float ia, float or_, float og, float ob, float oa) {
    gui->drawBezierArrow(width, p1, c1, c2, p2, {ir, ig, ib, ia}, {or_, og, ob, oa});
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
    L.push("THORVG");
    L.newtable();

    REGISTER(L, tvg_accessor_del);
    REGISTER(L, tvg_accessor_generate_id);
    REGISTER(L, tvg_accessor_get_name);
    REGISTER(L, tvg_accessor_new);
    REGISTER(L, tvg_accessor_set);
    REGISTER(L, tvg_animation_del);
    REGISTER(L, tvg_animation_get_duration);
    REGISTER(L, tvg_animation_get_frame);
    REGISTER(L, tvg_animation_get_picture);
    REGISTER(L, tvg_animation_get_segment);
    REGISTER(L, tvg_animation_get_total_frame);
    REGISTER(L, tvg_animation_new);
    REGISTER(L, tvg_animation_set_frame);
    REGISTER(L, tvg_animation_set_segment);
    REGISTER(L, tvg_canvas_add);
    REGISTER(L, tvg_canvas_destroy);
    REGISTER(L, tvg_canvas_draw);
    REGISTER(L, tvg_canvas_insert);
    REGISTER(L, tvg_canvas_remove);
    REGISTER(L, tvg_canvas_set_viewport);
    REGISTER(L, tvg_canvas_sync);
    REGISTER(L, tvg_canvas_update);
    REGISTER(L, tvg_engine_init);
    REGISTER(L, tvg_engine_term);
    REGISTER(L, tvg_engine_version);
    REGISTER(L, tvg_font_load);
    REGISTER(L, tvg_font_load_data);
    REGISTER(L, tvg_font_unload);
    REGISTER(L, tvg_glcanvas_create);
    REGISTER(L, tvg_glcanvas_set_target);
    REGISTER(L, tvg_gradient_del);
    REGISTER(L, tvg_gradient_duplicate);
    REGISTER(L, tvg_gradient_get_color_stops);
    REGISTER(L, tvg_gradient_get_spread);
    REGISTER(L, tvg_gradient_get_transform);
    REGISTER(L, tvg_gradient_get_type);
    REGISTER(L, tvg_gradient_set_color_stops);
    REGISTER(L, tvg_gradient_set_spread);
    REGISTER(L, tvg_gradient_set_transform);
    REGISTER(L, tvg_linear_gradient_get);
    REGISTER(L, tvg_linear_gradient_new);
    REGISTER(L, tvg_linear_gradient_set);
    REGISTER(L, tvg_lottie_animation_apply_slot);
    REGISTER(L, tvg_lottie_animation_del_slot);
    REGISTER(L, tvg_lottie_animation_expressions_supported);
    REGISTER(L, tvg_lottie_animation_gen_slot);
    REGISTER(L, tvg_lottie_animation_get_marker);
    REGISTER(L, tvg_lottie_animation_get_marker_info);
    REGISTER(L, tvg_lottie_animation_get_markers_cnt);
    REGISTER(L, tvg_lottie_animation_get_volume);
    REGISTER(L, tvg_lottie_animation_new);
    REGISTER(L, tvg_lottie_animation_set_audio_resolver);
    REGISTER(L, tvg_lottie_animation_set_marker);
    REGISTER(L, tvg_lottie_animation_set_quality);
    REGISTER(L, tvg_lottie_animation_set_volume);
    REGISTER(L, tvg_lottie_animation_tween);
    REGISTER(L, tvg_lottie_animation_tween_go);
    REGISTER(L, tvg_lottie_animation_tween_to);
    REGISTER(L, tvg_paint_duplicate);
    REGISTER(L, tvg_paint_get_aabb);
    REGISTER(L, tvg_paint_get_clip);
    REGISTER(L, tvg_paint_get_data);
    REGISTER(L, tvg_paint_get_id);
    REGISTER(L, tvg_paint_get_mask_method);
    REGISTER(L, tvg_paint_get_obb);
    REGISTER(L, tvg_paint_get_opacity);
    REGISTER(L, tvg_paint_get_parent);
    REGISTER(L, tvg_paint_get_ref);
    REGISTER(L, tvg_paint_get_transform);
    REGISTER(L, tvg_paint_get_type);
    REGISTER(L, tvg_paint_get_visible);
    REGISTER(L, tvg_paint_intersects);
    REGISTER(L, tvg_paint_intersects_region);
    REGISTER(L, tvg_paint_ref);
    REGISTER(L, tvg_paint_rel);
    REGISTER(L, tvg_paint_rotate);
    REGISTER(L, tvg_paint_scale);
    REGISTER(L, tvg_paint_set_blend_method);
    REGISTER(L, tvg_paint_set_clip);
    REGISTER(L, tvg_paint_set_data);
    REGISTER(L, tvg_paint_set_id);
    REGISTER(L, tvg_paint_set_mask_method);
    REGISTER(L, tvg_paint_set_opacity);
    REGISTER(L, tvg_paint_set_transform);
    REGISTER(L, tvg_paint_set_visible);
    REGISTER(L, tvg_paint_translate);
    REGISTER(L, tvg_paint_unref);
    REGISTER(L, tvg_picture_get_origin);
    REGISTER(L, tvg_picture_get_paint);
    REGISTER(L, tvg_picture_get_size);
    REGISTER(L, tvg_picture_load);
    REGISTER(L, tvg_picture_load_data);
    REGISTER(L, tvg_picture_load_raw);
    REGISTER(L, tvg_picture_new);
    REGISTER(L, tvg_picture_set_accessible);
    REGISTER(L, tvg_picture_set_asset_resolver);
    REGISTER(L, tvg_picture_set_filter);
    REGISTER(L, tvg_picture_set_origin);
    REGISTER(L, tvg_picture_set_size);
    REGISTER(L, tvg_radial_gradient_get);
    REGISTER(L, tvg_radial_gradient_new);
    REGISTER(L, tvg_radial_gradient_set);
    REGISTER(L, tvg_saver_del);
    REGISTER(L, tvg_saver_new);
    REGISTER(L, tvg_saver_save_animation);
    REGISTER(L, tvg_saver_save_paint);
    REGISTER(L, tvg_saver_sync);
    REGISTER(L, tvg_scene_add);
    REGISTER(L, tvg_scene_add_effect_drop_shadow);
    REGISTER(L, tvg_scene_add_effect_fill);
    REGISTER(L, tvg_scene_add_effect_gaussian_blur);
    REGISTER(L, tvg_scene_add_effect_tint);
    REGISTER(L, tvg_scene_add_effect_tritone);
    REGISTER(L, tvg_scene_clear_effects);
    REGISTER(L, tvg_scene_insert);
    REGISTER(L, tvg_scene_new);
    REGISTER(L, tvg_scene_remove);
    REGISTER(L, tvg_shape_append_circle);
    REGISTER(L, tvg_shape_append_path);
    REGISTER(L, tvg_shape_append_rect);
    REGISTER(L, tvg_shape_close);
    REGISTER(L, tvg_shape_cubic_to);
    REGISTER(L, tvg_shape_get_fill_color);
    REGISTER(L, tvg_shape_get_fill_rule);
    REGISTER(L, tvg_shape_get_gradient);
    REGISTER(L, tvg_shape_get_path);
    REGISTER(L, tvg_shape_get_stroke_cap);
    REGISTER(L, tvg_shape_get_stroke_color);
    REGISTER(L, tvg_shape_get_stroke_dash);
    REGISTER(L, tvg_shape_get_stroke_gradient);
    REGISTER(L, tvg_shape_get_stroke_join);
    REGISTER(L, tvg_shape_get_stroke_miterlimit);
    REGISTER(L, tvg_shape_get_stroke_width);
    REGISTER(L, tvg_shape_line_to);
    REGISTER(L, tvg_shape_move_to);
    REGISTER(L, tvg_shape_new);
    REGISTER(L, tvg_shape_reset);
    REGISTER(L, tvg_shape_set_fill_color);
    REGISTER(L, tvg_shape_set_fill_rule);
    REGISTER(L, tvg_shape_set_gradient);
    REGISTER(L, tvg_shape_set_paint_order);
    REGISTER(L, tvg_shape_set_stroke_cap);
    REGISTER(L, tvg_shape_set_stroke_color);
    REGISTER(L, tvg_shape_set_stroke_dash);
    REGISTER(L, tvg_shape_set_stroke_gradient);
    REGISTER(L, tvg_shape_set_stroke_join);
    REGISTER(L, tvg_shape_set_stroke_miterlimit);
    REGISTER(L, tvg_shape_set_stroke_width);
    REGISTER(L, tvg_shape_set_trimpath);
    REGISTER(L, tvg_swcanvas_create);
    REGISTER(L, tvg_swcanvas_set_target);
    REGISTER(L, tvg_text_align);
    REGISTER(L, tvg_text_get_glyph_metrics);
    REGISTER(L, tvg_text_get_text);
    REGISTER(L, tvg_text_get_text_metrics);
    REGISTER(L, tvg_text_layout);
    REGISTER(L, tvg_text_line_count);
    REGISTER(L, tvg_text_new);
    REGISTER(L, tvg_text_set_color);
    REGISTER(L, tvg_text_set_font);
    REGISTER(L, tvg_text_set_gradient);
    REGISTER(L, tvg_text_set_italic);
    REGISTER(L, tvg_text_set_outline);
    REGISTER(L, tvg_text_set_size);
    REGISTER(L, tvg_text_set_text);
    REGISTER(L, tvg_text_spacing);
    REGISTER(L, tvg_text_wrap_mode);
    REGISTER(L, tvg_video_del);
    REGISTER(L, tvg_video_get_duration);
    REGISTER(L, tvg_video_get_loop);
    REGISTER(L, tvg_video_get_muted);
    REGISTER(L, tvg_video_get_picture);
    REGISTER(L, tvg_video_get_time);
    REGISTER(L, tvg_video_get_volume);
    REGISTER(L, tvg_video_new);
    REGISTER(L, tvg_video_pause);
    REGISTER(L, tvg_video_play);
    REGISTER(L, tvg_video_seek);
    REGISTER(L, tvg_video_set_loop);
    REGISTER(L, tvg_video_set_mute);
    REGISTER(L, tvg_video_set_volume);
    REGISTER(L, tvg_video_stop);
    REGISTER(L, tvg_wgcanvas_create);
    REGISTER(L, tvg_wgcanvas_set_target);
    REGISTER(L, tvg_wgcanvas_set_target_with_context);

    REGISTER(L, tvgReduxGetViewportScene);
    REGISTER(L, tvgReduxDrawBezierArrow);

    L.settable();
    L.pop();
}

}  // namespace

void PCSX::LuaFFI::open_tvg(GUI* gui, Lua L) {
    registerAllSymbols(L);
    static int lualoader = 2;
    static const char* tvg_cdefs = (
#include "gui/tvgffi-cdefs.lua"
    );
    static const char* tvg = (
#include "gui/tvgffi.lua"
    );
    L.load(tvg_cdefs, "src:gui/tvgffi-cdefs.lua");
    L.load(tvg, "src:gui/tvgffi.lua");
    L.getfieldtable("tvg", LUA_GLOBALSINDEX);
    L.push("_gui");
    L.push(gui);
    L.settable();
    L.pop();
}
