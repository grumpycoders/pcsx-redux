/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <utility>

#include "GL/gl3w.h"

#define IMGUI_DEFINE_MATH_OPERATORS
#include "imgui.h"
#include "imgui_internal.h"

#include "core/system.h"
#include "gui/gui.h"
#include "gui/widgets/vram-viewer.h"

static const GLchar *s_defaultVertexShader = GL_SHADER_VERSION R"(
precision highp float;
in vec2 i_position;
in vec2 i_texUV;
uniform mat4 u_projMatrix;
out vec2 fragUV;

void main() {
    fragUV = i_texUV;
    gl_Position = u_projMatrix * vec4(i_position.xy, 0.0f, 1.0f);
}
)";

static const GLchar *s_defaultPixelShader = GL_SHADER_VERSION R"(
precision highp float;
uniform sampler2D u_vramTexture;
uniform vec2 u_origin;
uniform vec2 u_resolution;
uniform vec2 u_mousePos;
uniform bool u_hovered;
uniform bool u_alpha;
uniform int u_mode;
uniform vec2 u_mouseUV;
uniform vec2 u_cornerTL;
uniform vec2 u_cornerBR;
uniform int u_24shift;
in vec2 fragUV;
out vec4 outColor;
layout(origin_upper_left) in vec4 gl_FragCoord;

uniform bool u_magnify;
uniform float u_magnifyRadius;
uniform float u_magnifyAmount;
const float ridge = 1.5f;

uniform bool u_greyscale;
uniform vec2 u_clut;

const vec4 grey1 = vec4(0.6f, 0.6f, 0.6f, 1.0f);
const vec4 grey2 = vec4(0.8f, 0.8f, 0.8f, 1.0f);

int texelToRaw(in vec4 t) {
    int c = (int(t.r * 31.0f + 0.5f) <<  0) |
            (int(t.g * 31.0f + 0.5f) <<  5) |
            (int(t.b * 31.0f + 0.5f) << 10) |
            (int(t.a) << 15);
    return c;
}

vec4 readTexture(in vec2 pos) {
    vec2 apos = vec2(1024.0f, 512.0f) * pos;
    vec2 fpos = fract(apos);
    ivec2 ipos = ivec2(apos);
    vec4 ret = vec4(0.0f);
    if (pos.x > 1.0f) return ret;
    if (pos.y > 1.0f) return ret;
    if (pos.x < 0.0f) return ret;
    if (pos.y < 0.0f) return ret;

    float scale = 0.0f;
    int p = 0;
    vec4 t = texture(u_vramTexture, pos);
    int c = texelToRaw(t);

    switch (u_mode) {
    case 0:
        {
            ret.a = 1.0f;
            vec4 tb = texture(u_vramTexture, pos - vec2(1.0 / 1024.0f, 0.0f));
            vec4 ta = texture(u_vramTexture, pos + vec2(1.0 / 1024.0f, 0.0f));
            int cb = texelToRaw(tb);
            int ca = texelToRaw(ta);
            switch ((ipos.x + u_24shift) % 3) {
                case 0:
                    ret.r = float((c >> 0) & 0xff) / 255.0f;
                    ret.g = float((c >> 8) & 0xff) / 255.0f;
                    ret.b = float((ca >> 0) & 0xff) / 255.0f;
                    break;
                case 1:
                    if (fpos.x < 0.5f) {
                        ret.r = float((cb >> 0) & 0xff) / 255.0f;
                        ret.g = float((cb >> 8) & 0xff) / 255.0f;
                        ret.b = float((c >> 0) & 0xff) / 255.0f;
                    } else {
                        ret.r = float((c >> 8) & 0xff) / 255.0f;
                        ret.g = float((ca >> 0) & 0xff) / 255.0f;
                        ret.b = float((ca >> 8) & 0xff) / 255.0f;
                    }
                    break;
                case 2:
                    ret.r = float((cb >> 8) & 0xff) / 255.0f;
                    ret.g = float((c >> 0) & 0xff) / 255.0f;
                    ret.b = float((c >> 8) & 0xff) / 255.0f;
                    break;
            }
        }
        break;
    case 1:
        ret = t;
        break;
    case 2:
        scale = 255.0f;
        if (fpos.x < 0.5f) {
            p = (c >> 0) & 0xff;
        } else {
            p = (c >> 8) & 0xff;
        }
        break;
    case 3:
        scale = 15.0f;
        if (fpos.x < 0.25f) {
            p = (c >> 0) & 0xf;
        } else if (fpos.x < 0.5f) {
            p = (c >> 4) & 0xf;
        } else if (fpos.x < 0.75f) {
            p = (c >> 8) & 0xf;
        } else {
            p = (c >> 12) & 0xf;
        }
        break;
    }

    if (u_mode >= 2) {
        if (u_greyscale) {
            ret = vec4(float(p) / scale);
            ret.a = 1.0f;
        } else {
            ret = texture(u_vramTexture, u_clut + vec2(float(p) * 1.0f / 1024.0f, 0.0f));
        }
    } else if (u_greyscale) {
         ret = vec4(0.299, 0.587, 0.114, 0.0f) * ret;
         ret = vec4(ret.r + ret.g + ret.b);
         ret.a = 1.0f;
    }

    return ret;
}

void main() {
    float magnifyAmount = u_magnifyAmount;
    vec2 fragCoord = gl_FragCoord.xy - u_origin;
    vec4 fragColor = readTexture(fragUV.st);
    vec2 magnifyVector = (fragUV.st - u_mouseUV) / u_magnifyAmount;
    vec4 magnifyColor = readTexture(magnifyVector + u_mouseUV);

    float blend = u_magnify ?
        smoothstep(u_magnifyRadius + ridge, u_magnifyRadius, distance(fragCoord, u_mousePos)) :
        0.0f;

    outColor = mix(fragColor, magnifyColor, blend);

    if (u_alpha) {
        int x = int(fragCoord.x);
        int y = int(fragCoord.y);
        int info = (x >> 4) + (y >> 4);
        vec4 back = (info & 1) == 0 ? grey1 : grey2;
        outColor = mix(back, outColor, outColor.a);
    }
    outColor.a = 1.0f;
}
)";

void PCSX::Widgets::VRAMViewer::compileShader(const char *VS, const char *PS) {
    GLint status = 0;

    GLuint vertexShader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertexShader, 1, &VS, 0);
    glCompileShader(vertexShader);

    glGetShaderiv(vertexShader, GL_COMPILE_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetShaderiv(vertexShader, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);
        glGetShaderInfoLog(vertexShader, maxLength, &maxLength, log);

        m_errorMessage = std::string(_("Vertex Shader compilation error:\n")) + log;

        free(log);
        glDeleteShader(vertexShader);
        PCSX::GUI::checkGL();
        return;
    }

    GLuint pixelShader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(pixelShader, 1, &PS, 0);
    glCompileShader(pixelShader);

    glGetShaderiv(pixelShader, GL_COMPILE_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetShaderiv(pixelShader, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);

        glGetShaderInfoLog(pixelShader, maxLength, &maxLength, log);

        m_errorMessage = std::string(_("Pixel Shader compilation error:\n")) + log;

        free(log);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        PCSX::GUI::checkGL();
        return;
    }

    GLuint shaderProgram = glCreateProgram();
    glAttachShader(shaderProgram, vertexShader);
    glAttachShader(shaderProgram, pixelShader);

    glLinkProgram(shaderProgram);

    glGetProgramiv(shaderProgram, GL_LINK_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetProgramiv(shaderProgram, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);

        glGetProgramInfoLog(shaderProgram, maxLength, &maxLength, log);

        m_errorMessage = std::string(_("Link error:\n")) + log;

        free(log);
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        PCSX::GUI::checkGL();
        return;
    }

    int attribLocationVtxPos = glGetAttribLocation(shaderProgram, "i_position");
    int attribLocationVtxUV = glGetAttribLocation(shaderProgram, "i_texUV");

    if ((attribLocationVtxPos == -1) || (attribLocationVtxUV == -1)) {
        m_errorMessage = "Missing i_position and/or i_texUV locations";
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(pixelShader);
        PCSX::GUI::checkGL();
        return;
    }

    destroy();
    glDeleteShader(vertexShader);
    glDeleteShader(pixelShader);

    m_shaderProgram = shaderProgram;
    m_attribLocationTex = glGetUniformLocation(m_shaderProgram, "u_vramTexture");
    m_attribLocationProjMtx = glGetUniformLocation(m_shaderProgram, "u_projMatrix");
    m_attribLocationHovered = glGetUniformLocation(m_shaderProgram, "u_hovered");
    m_attribLocationMousePos = glGetUniformLocation(m_shaderProgram, "u_mousePos");
    m_attribLocationMouseUV = glGetUniformLocation(m_shaderProgram, "u_mouseUV");
    m_attribLocationResolution = glGetUniformLocation(m_shaderProgram, "u_resolution");
    m_attribLocationOrigin = glGetUniformLocation(m_shaderProgram, "u_origin");
    m_attribLocationMagnify = glGetUniformLocation(m_shaderProgram, "u_magnify");
    m_attribLocationMagnifyRadius = glGetUniformLocation(m_shaderProgram, "u_magnifyRadius");
    m_attribLocationMagnifyAmount = glGetUniformLocation(m_shaderProgram, "u_magnifyAmount");
    m_attribLocationCornerTL = glGetUniformLocation(m_shaderProgram, "u_cornerTL");
    m_attribLocationCornerBR = glGetUniformLocation(m_shaderProgram, "u_cornerBR");
    m_attribLocationAlpha = glGetUniformLocation(m_shaderProgram, "u_alpha");
    m_attribLocationGreyscale = glGetUniformLocation(m_shaderProgram, "u_greyscale");
    m_attribLocationMode = glGetUniformLocation(m_shaderProgram, "u_mode");
    m_attribLocationClut = glGetUniformLocation(m_shaderProgram, "u_clut");
    m_attribLocation24shift = glGetUniformLocation(m_shaderProgram, "u_24shift");
    m_attribLocationVtxPos = attribLocationVtxPos;
    m_attribLocationVtxUV = attribLocationVtxUV;

    m_errorMessage = "";
    PCSX::GUI::checkGL();
}

void PCSX::Widgets::VRAMViewer::init() {
    m_vertexShaderEditor.SetText(s_defaultVertexShader);
    m_pixelShaderEditor.SetText(s_defaultPixelShader);
    compileShader(s_defaultVertexShader, s_defaultPixelShader);
    SDL_assert(m_shaderProgram);
}

void PCSX::Widgets::VRAMViewer::destroy() {
    if (m_shaderProgram) glDeleteProgram(m_shaderProgram);
    PCSX::GUI::checkGL();
}

void PCSX::Widgets::VRAMViewer::drawVRAM(unsigned int textureID) {
    m_textureID = textureID;
    m_resolution = ImGui::GetContentRegionAvail();
    m_origin = ImGui::GetCursorScreenPos();
    auto basePos = ImGui::GetWindowViewport()->Pos;
    auto mousePos = ImGui::GetIO().MousePos - basePos;
    m_mousePos = mousePos - m_origin;

    ImDrawList *drawList = ImGui::GetWindowDrawList();
    drawList->AddCallback(imguiCBtrampoline, this);

    // TexCoord - (TexturePoint - ResolutionPoint) / dimensions
    // TexCoordTL = 0, 0
    // TexCoordBR = 1, 1
    // ResolutionTL = 0, 0
    // ResolutionBR = m_resolution
    // --> texTL = 0 - (cornerTL - 0) / dimensions = -corner / dimensions
    // --> texBR = 1 - (cornerBR - m_resolution) / dimensions
    ImVec2 dimensions = m_cornerBR - m_cornerTL;
    ImVec2 texTL = ImVec2(0.0f, 0.0f) - m_cornerTL / dimensions;
    ImVec2 texBR = ImVec2(1.0f, 1.0f) - (m_cornerBR - m_resolution) / dimensions;
    ImGui::Image(reinterpret_cast<ImTextureID*>(textureID), m_resolution, texTL, texBR);
    if (m_clutDestination && m_selectingClut) {
        m_clutDestination->m_clut = m_mouseUV;
    }

    m_hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_None);
    if (ImGui::IsItemClicked()) m_selectingClut = false;

    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);

    const auto &io = ImGui::GetIO();

    ImVec2 texSpan = texBR - texTL;
    m_mouseUV = texTL + texSpan * (m_mousePos + basePos) / m_resolution;

    if (!m_hovered) {
        m_magnify = false;
        return;
    }
    m_magnify = io.KeyCtrl;
    if (io.MouseWheel != 0.0f) {
        if (io.KeyCtrl) {
            if (io.KeyShift) {
                m_magnifyRadius += io.MouseWheel * 10.0f;
                if (m_magnifyRadius <= 0.0f) m_magnifyRadius = 0.0f;
            } else {
                m_magnifyAmount += io.MouseWheel;
                while ((-1.0f <= m_magnifyAmount) && (m_magnifyAmount <= 1.0f)) m_magnifyAmount += io.MouseWheel;
            }
        } else {
            static const float increment = 1.2f;
            const float step = io.MouseWheel > 0.0f ? increment * io.MouseWheel : -1.0f / (increment * io.MouseWheel);

            ImVec2 newDimensions = dimensions * step;
            ImVec2 dimensionsDiff = newDimensions - dimensions;
            m_cornerTL -= dimensionsDiff * m_mouseUV;
            m_cornerBR = m_cornerTL + newDimensions;
        }
    } else if (io.MouseDown[2]) {
        m_cornerTL += io.MouseDelta;
        m_cornerBR = m_cornerTL + dimensions;
    }
}

void PCSX::Widgets::VRAMViewer::drawEditor() {
    auto contents = ImGui::GetContentRegionAvail();
    ImGuiStyle &style = ImGui::GetStyle();
    const float heightSeparator = style.ItemSpacing.y;
    float footerHeight = heightSeparator * 2 + 5 * ImGui::GetTextLineHeightWithSpacing();
    float width = contents.x / 2 - style.ItemInnerSpacing.x;
    m_vertexShaderEditor.Render(_("Vertex Shader"), ImVec2(width, -footerHeight), true);
    ImGui::SameLine();
    m_pixelShaderEditor.Render(_("Pixel Shader"), ImVec2(width, -footerHeight), true);
    ImGui::BeginChild("Errors", ImVec2(0, 0), true);
    ImGui::Text("%s", m_errorMessage.c_str());
    ImGui::EndChild();

    if (m_vertexShaderEditor.IsTextChanged() || m_pixelShaderEditor.IsTextChanged()) {
        compileShader(m_vertexShaderEditor.GetText().c_str(), m_pixelShaderEditor.GetText().c_str());
    }
}

void PCSX::Widgets::VRAMViewer::imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd) {
    GLint imguiProgramID;
    glGetIntegerv(GL_CURRENT_PROGRAM, &imguiProgramID);

    GLint projMatrixLocation = glGetUniformLocation(imguiProgramID, "ProjMtx");

    GLfloat currentProjection[4][4];
    glGetUniformfv(imguiProgramID, projMatrixLocation, &currentProjection[0][0]);

    glUseProgram(m_shaderProgram);
    glUniform1i(m_attribLocationTex, 0);
    glUniformMatrix4fv(m_attribLocationProjMtx, 1, GL_FALSE, &currentProjection[0][0]);
    glUniform1i(m_attribLocationHovered, m_hovered);
    glUniform2f(m_attribLocationMousePos, m_mousePos.x, m_mousePos.y);
    glUniform2f(m_attribLocationMouseUV, m_mouseUV.x, m_mouseUV.y);
    glUniform2f(m_attribLocationResolution, m_resolution.x, m_resolution.y);
    glUniform2f(m_attribLocationOrigin, m_origin.x, m_origin.y);
    glUniform1i(m_attribLocationMagnify, m_magnify);
    if (m_magnifyAmount < 0.0f) {
        glUniform1f(m_attribLocationMagnifyAmount, -1.0f / m_magnifyAmount);
    } else {
        glUniform1f(m_attribLocationMagnifyAmount, m_magnifyAmount);
    }
    glUniform1f(m_attribLocationMagnifyRadius, m_magnifyRadius);
    glUniform2f(m_attribLocationCornerTL, m_cornerTL.x, m_cornerTL.y);
    glUniform2f(m_attribLocationCornerBR, m_cornerBR.x, m_cornerBR.y);
    glUniform1i(m_attribLocationAlpha, m_alpha);
    if (!m_hasClut && m_vramMode >= 2) {
        glUniform1i(m_attribLocationGreyscale, 1);
    } else {
        glUniform1i(m_attribLocationGreyscale, m_greyscale);
    }
    glUniform1i(m_attribLocationMode, m_vramMode);
    glUniform2f(m_attribLocationClut, m_clut.x, m_clut.y);
    glUniform1i(m_attribLocation24shift, m_24shift);
    glEnableVertexAttribArray(m_attribLocationVtxPos);
    glEnableVertexAttribArray(m_attribLocationVtxUV);
    glVertexAttribPointer(m_attribLocationVtxPos, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, pos));
    glVertexAttribPointer(m_attribLocationVtxUV, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, uv));
    glBindTexture(GL_TEXTURE_2D, m_textureID);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    PCSX::GUI::checkGL();
}

void PCSX::Widgets::VRAMViewer::resetView() {
    m_cornerTL = {0.0f, 0.0f};
    m_cornerBR = {512.0f / RATIOS[m_vramMode], 512.0f};
    m_cornerBR *= ImGui::GetWindowDpiScale();
    m_magnifyAmount = 5.0f;
    m_magnifyRadius = 150.0f * ImGui::GetWindowDpiScale();
}

void PCSX::Widgets::VRAMViewer::render(unsigned int VRAMTexture) {
    if (m_show) {
        auto flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_MenuBar;
        if (ImGui::Begin(m_title().c_str(), &m_show, flags)) {
            if (!m_firstShown) {
                resetView();
                m_firstShown = true;
            }
            if (ImGui::BeginMenuBar()) {
                if (ImGui::BeginMenu(_("File"))) {
                    ImGui::EndMenu();
                }
                if (ImGui::BeginMenu(_("View"))) {
                    if (ImGui::MenuItem(_("Reset view"))) resetView();
                    if (!m_clutDestination) {
                        ImGui::Separator();
                        ImGui::SliderInt(_("24 bits shift"), &m_24shift, 0, 2);
                        if (ImGui::MenuItem(_("View VRAM in 24 bits"), nullptr, m_vramMode == VRAM_24BITS)) {
                            m_vramMode = VRAM_24BITS;
                            modeChanged();
                        }
                        if (ImGui::MenuItem(_("View VRAM in 16 bits"), nullptr, m_vramMode == VRAM_16BITS)) {
                            m_vramMode = VRAM_16BITS;
                            modeChanged();
                        }
                        if (ImGui::MenuItem(_("View VRAM in 8 bits"), nullptr, m_vramMode == VRAM_8BITS)) {
                            m_vramMode = VRAM_8BITS;
                            modeChanged();
                        }
                        if (ImGui::MenuItem(_("View VRAM in 4 bits"), nullptr, m_vramMode == VRAM_4BITS)) {
                            m_vramMode = VRAM_4BITS;
                            modeChanged();
                        }
                    } else {
                        ImGui::MenuItem(_("Select a CLUT"), nullptr, &m_selectingClut);
                    }
                    ImGui::MenuItem(_("Enable Alpha channel view"), nullptr, &m_alpha);
                    ImGui::MenuItem(_("Enable greyscale"), nullptr, &m_greyscale);
                    ImGui::Separator();
                    ImGui::MenuItem(_("Show Shader Editor"), nullptr, &m_showEditor);
                    ImGui::EndMenu();
                }
                ImGui::EndMenuBar();
            }
            drawVRAM(VRAMTexture);
        }
        ImGui::End();
    }

    if (m_showEditor) {
        if (ImGui::Begin(_("VRAM Shader Editor"), &m_showEditor)) {
            drawEditor();
        }
        ImGui::End();
    }
}

void PCSX::Widgets::VRAMViewer::modeChanged() {
    ImVec2 dimensions = m_cornerBR - m_cornerTL;
    ImVec2 texTL = ImVec2(0.0f, 0.0f) - m_cornerTL / dimensions;
    ImVec2 texBR = ImVec2(1.0f, 1.0f) - (m_cornerBR - m_resolution) / dimensions;
    float focusX = texTL.x + (texBR.x - texTL.x) / 2.0f;
    float newX = dimensions.y / RATIOS[m_vramMode];
    float deltaX = newX - dimensions.x;
    m_cornerTL.x = m_cornerTL.x - deltaX * focusX;
    m_cornerBR.x = m_cornerTL.x + newX;
}
