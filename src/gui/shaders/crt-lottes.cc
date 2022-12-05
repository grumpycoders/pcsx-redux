/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "gui/shaders/crt-lottes.h"

#include "gui/gui.h"

std::string_view PCSX::Shaders::CrtLottes::Output::vert() {
    return GL_SHADER_VERSION R"(
precision highp float;
layout (location = 0) in vec2 Position;
layout (location = 1) in vec2 UV;
layout (location = 2) in vec4 Color;
uniform mat4 u_projMatrix;
out vec2 Frag_UV;
out vec4 Frag_Color;
void main() {
    Frag_UV = UV;
    Frag_Color = Color;
    gl_Position = u_projMatrix * vec4(Position.xy, 0, 1);
}
)";
}

std::string_view PCSX::Shaders::CrtLottes::Output::frag() {
    return GL_SHADER_VERSION R"(
// stolen^H^H^H^H^H^Hinspired from https://www.shadertoy.com/view/XsjSzR
// from Timothy Lottes

precision highp float;
uniform sampler2D Texture;

uniform vec2 u_srcSize;
uniform vec2 u_dstSize;
uniform float u_mask;
uniform float u_warp;
uniform int u_masktype;
uniform bool u_grey;

float maskDark;
float maskLight;
vec2 c_warp;

vec2 warp(vec2 pos) {
    pos = pos * 2.0 - 1.0;
    pos *= vec2(1.0 + (pos.y * pos.y) * c_warp.x, 1.0 + (pos.x * pos.x) * c_warp.y);
    pos = pos * 0.5 + 0.5;
    return pos;
}

vec3 toGrey(vec3 rgb) {
    vec3 ret = rgb;
    ret = rgb * vec3(0.299, 0.587, 0.114);
    return vec3(ret.r + ret.g + ret.b);
}

vec3 mask(vec2 pos) {
    pos *= u_srcSize;
    vec3 m = vec3(maskDark);

    switch(u_masktype) {
        case 1:
            pos *= 2.0;
            break;
        case 2:
            break;
        case 3:
            pos = pos - fract(pos);
            pos.x += pos.y * 3.0;
            break;
    }

    pos.x = fract(pos.x / 6.0);
    if (pos.x < 0.333) m.r = maskLight;
    else if (pos.x < 0.666) m.g = maskLight;
    else m.b = maskLight;
    return m;
}

vec3 fetch(vec2 pos) {
    if (pos.x < 0.0) return vec3(0.0);
    if (pos.y < 0.0) return vec3(0.0);
    if (pos.x > 1.0) return vec3(0.0);
    if (pos.y > 1.0) return vec3(0.0);
    return texture(Texture, pos).rgb;
}

in vec2 Frag_UV;
layout (location = 0) out vec4 Out_Color;
void main() {
    maskDark = 1.0 - u_mask;
    maskLight = 1.0 + u_mask;
    c_warp = vec2(u_warp / 32.0, u_warp / 24.0);

    Out_Color.rgb = fetch(warp(Frag_UV.st));
    if (u_grey) {
        Out_Color.rgb = toGrey(Out_Color.rgb);
    }
    Out_Color.rgb *= mask(Frag_UV.st);
    Out_Color.a = 1.0;
}
)";
}

std::string_view PCSX::Shaders::CrtLottes::Output::lua() {
    static int lualoader = 1;
    static const char* lua = (
#include "gui/shaders/crt-lottes-output.lua"
    );
    return lua;
}

std::string_view PCSX::Shaders::CrtLottes::Offscreen::vert() {
    return GL_SHADER_VERSION R"(
precision highp float;
layout (location = 0) in vec2 Position;
layout (location = 1) in vec2 UV;
layout (location = 2) in vec4 Color;
uniform mat4 u_projMatrix;
out vec2 Frag_UV;
out vec4 Frag_Color;
void main() {
    Frag_UV = UV;
    Frag_Color = Color;
    gl_Position = u_projMatrix * vec4(Position.xy, 0, 1);
}
)";
}

std::string_view PCSX::Shaders::CrtLottes::Offscreen::frag() {
    return GL_SHADER_VERSION R"(
// stolen^H^H^H^H^H^Hinspired from https://www.shadertoy.com/view/XsjSzR
// from Timothy Lottes

precision highp float;

uniform sampler2D Texture;
in vec2 Frag_UV;
uniform vec2 u_srcLoc;
uniform vec2 u_srcSize;
uniform vec2 u_dstSize;
uniform float u_hardPix;
uniform float u_hardScan;
uniform bool u_useSrgb;
uniform bool u_enabled;
uniform bool u_scanlines;

layout (location = 0) out vec4 Out_Color;

vec2 c_scale = vec2(1024.0, 512.0);
vec2 c_res;
vec2 c_pixelUV;

// sRGB to Linear.
// Assuming using sRGB typed textures this should not be needed.
float toLinear1(float c) { return (c <= 0.04045) ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4); }
vec3 toLinear(vec3 c) { return vec3(toLinear1(c.r), toLinear1(c.g), toLinear1(c.b)); }

// Linear to sRGB.
// Assuming using sRGB typed textures this should not be needed.
float toSrgb1(float c) { return (c < 0.0031308 ? c * 12.92 : 1.055 * pow(c, 0.41666) - 0.055); }
vec3 toSrgb(vec3 c) { return vec3(toSrgb1(c.r), toSrgb1(c.g), toSrgb1(c.b)); }

vec2 dist(vec2 pos) {
    return -((pos - floor(pos)) - vec2(0.5));
}

float gaus(float pos, float scale) { return exp2(scale * pos * pos); }

vec3 fetch(vec2 pixelPos, vec2 offset) {
    pixelPos += offset;
    vec2 normPos = pixelPos / c_scale;
    if (normPos.x < 0.0) return vec3(0.0);
    if (normPos.y < 0.0) return vec3(0.0);
    if (normPos.x > u_srcSize.x) return vec3(0.0);
    if (normPos.y > u_srcSize.y) return vec3(0.0);
    return texture(Texture, normPos + u_srcLoc).rgb;
}

float scan(vec2 pos, float off) {
    float dst = dist(pos).y;
    return gaus(dst + off, u_hardScan);
}

// 3-tap Gaussian filter along horz line.
vec3 horz3(vec2 pos, float off) {
    vec3 b = fetch(pos, vec2(-1.0, off));
    vec3 c = fetch(pos, vec2(0.0, off));
    vec3 d = fetch(pos, vec2(1.0, off));
    float dst = dist(pos).x;
    // Convert distance to weight.
    float scale = u_hardPix;
    float wb = gaus(dst - 1.0, scale);
    float wc = gaus(dst + 0.0, scale);
    float wd = gaus(dst + 1.0, scale);
    // Return filtered sample.
    return (b * wb + c * wc + d * wd) / (wb + wc + wd);
}

// 5-tap Gaussian filter along horz line.
vec3 horz5(vec2 pos, float off) {
    vec3 a = fetch(pos, vec2(-2.0, off));
    vec3 b = fetch(pos, vec2(-1.0, off));
    vec3 c = fetch(pos, vec2(0.0, off));
    vec3 d = fetch(pos, vec2(1.0, off));
    vec3 e = fetch(pos, vec2(2.0, off));
    float dst = dist(pos).x;
    // Convert distance to weight.
    float scale = u_hardPix;
    float wa = gaus(dst - 2.0, scale);
    float wb = gaus(dst - 1.0, scale);
    float wc = gaus(dst + 0.0, scale);
    float wd = gaus(dst + 1.0, scale);
    float we = gaus(dst + 2.0, scale);
    // Return filtered sample.
    return (a * wa + b * wb + c * wc + d * wd + e * we) / (wa + wb + wc + wd + we);
}

vec3 tri(vec2 pos) {
    if (u_scanlines) {
        vec3 a = horz3(pos, -1.0);
        vec3 b = horz5(pos, 0.0);
        vec3 c = horz3(pos, 1.0);
        float wa = scan(pos, -1.0);
        float wb = scan(pos, 0.0);
        float wc = scan(pos, 1.0);
        return a * wa + b * wb + c * wc;
    } else {
        return horz5(pos, 0.0);
    }
}

void main() {
    c_res = u_srcSize * c_scale;
    c_pixelUV = c_scale * (Frag_UV - u_srcLoc);

    vec2 pos = c_pixelUV;
    if (u_enabled) {
        Out_Color.rgb = tri(pos);
    } else {
        Out_Color.rgb = fetch(pos, vec2(0));
    }
    if (u_useSrgb) {
        Out_Color.rgb = toSrgb(Out_Color.rgb);
    }
    Out_Color.a = 1.0;
}
)";
}

std::string_view PCSX::Shaders::CrtLottes::Offscreen::lua() {
    static int lualoader = 1;
    static const char* lua = (
#include "gui/shaders/crt-lottes-offscreen.lua"
    );
    return lua;
}
