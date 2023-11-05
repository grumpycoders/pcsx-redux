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

#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <utility>

#include "GL/gl3w.h"

#define IMGUI_DEFINE_MATH_OPERATORS
#include "core/gpulogger.h"
#include "core/system.h"
#include "gui/gui.h"
#include "gui/widgets/vram-viewer.h"
#include "imgui.h"
#include "imgui_internal.h"
#include "support/imgui-helpers.h"

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

uniform int u_24shift;
uniform bool u_alpha;
uniform vec2 u_clut;
uniform vec2 u_cornerBR;
uniform vec2 u_cornerTL;
uniform bool u_hovered;
uniform bool u_greyscale;
uniform bool u_magnify;
uniform float u_magnifyRadius;
uniform float u_magnifyAmount;
uniform int u_mode;
uniform float u_monitorDPI;
uniform vec2 u_mousePos;
uniform vec2 u_mouseUV;
uniform vec4 u_readColor;
uniform vec2 u_resolution;
uniform vec2 u_origin;
uniform sampler2D u_vramTexture;
uniform vec4 u_writtenColor;
uniform sampler2D u_readHighlight;
uniform sampler2D u_writtenHighlight;

in vec2 fragUV;
out vec4 outColor;

const float ridge = 1.5f;

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
    case 3:
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
    case 2:
        ret = t;
        break;
    case 1:
        scale = 255.0f;
        if (fpos.x < 0.5f) {
            p = (c >> 0) & 0xff;
        } else {
            p = (c >> 8) & 0xff;
        }
        break;
    case 0:
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

    if (u_mode < 2) {
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

float sampleTexture(in sampler2D sampler, in ivec2 pos) {
    if ((pos.x < 0) || (pos.y < 0)) return 0.0;
    if ((pos.x >= 1024) || (pos.y >= 512)) return 0.0;
    return texture(sampler, vec2(float(pos.x) / 1024.0, float(pos.y) / 512.0)).r;
}

float sum9(in sampler2D sampler, in vec2 pos) {
    vec2 apos = vec2(1024.0f, 512.0f) * pos;
    ivec2 ipos = ivec2(apos);
    float sum = 0.0;
    for (int y = -1; y <= 1; y++) {
        for (int x = -1; x <= 1; x++) {
          sum += sampleTexture(sampler, ipos + ivec2(x, y));
        }
    }
    return sum / 9.0;
}

vec4 outlineColor(in sampler2D sampler, in vec4 color, in vec2 pos) {
    float sum = sum9(sampler, pos);
    if ((sum >= 0.999) || (sum <= 0.001)) return vec4(0.0, 0.0, 0.0, 0.0);
    return color;
}

void main() {
    float magnifyAmount = u_magnifyAmount;
    vec2 fragCoord = gl_FragCoord.xy - u_origin;
    vec4 fragColor = readTexture(fragUV.st);
    vec2 magnifyVector = (fragUV.st - u_mouseUV) / u_magnifyAmount;
    vec4 magnifyColor = readTexture(magnifyVector + u_mouseUV);

    vec4 readOutline = outlineColor(u_readHighlight, u_readColor, fragUV.st);
    fragColor = mix(fragColor, readOutline, readOutline.a);
    vec4 writtenOutline = outlineColor(u_writtenHighlight, u_writtenColor, fragUV.st);
    fragColor = mix(fragColor, writtenOutline, writtenOutline.a);
    vec2 mousePos = vec2(u_mousePos.x - u_origin.x * 2.0, u_resolution.y - u_mousePos.y);

    float blend = u_magnify ?
        smoothstep(u_magnifyRadius + ridge, u_magnifyRadius, distance(fragCoord, mousePos)) :
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

void PCSX::Widgets::VRAMViewer::compileShader(GUI *gui) {
    auto status = m_editor.compile(gui, {"i_position", "i_texUV"});
    if (!status.isOk()) return;

    m_shaderProgram = m_editor.getProgram();

    m_attribLocation24shift = glGetUniformLocation(m_shaderProgram, "u_24shift");
    m_attribLocationAlpha = glGetUniformLocation(m_shaderProgram, "u_alpha");
    m_attribLocationClut = glGetUniformLocation(m_shaderProgram, "u_clut");
    m_attribLocationCornerBR = glGetUniformLocation(m_shaderProgram, "u_cornerBR");
    m_attribLocationCornerTL = glGetUniformLocation(m_shaderProgram, "u_cornerTL");
    m_attribLocationGreyscale = glGetUniformLocation(m_shaderProgram, "u_greyscale");
    m_attribLocationHovered = glGetUniformLocation(m_shaderProgram, "u_hovered");
    m_attribLocationMagnify = glGetUniformLocation(m_shaderProgram, "u_magnify");
    m_attribLocationMagnifyAmount = glGetUniformLocation(m_shaderProgram, "u_magnifyAmount");
    m_attribLocationMagnifyRadius = glGetUniformLocation(m_shaderProgram, "u_magnifyRadius");
    m_attribLocationMode = glGetUniformLocation(m_shaderProgram, "u_mode");
    m_attribLocationMonitorDPI = glGetUniformLocation(m_shaderProgram, "u_monitorDPI");
    m_attribLocationMonitorPosition = glGetUniformLocation(m_shaderProgram, "u_monitorPosition");
    m_attribLocationMonitorResolution = glGetUniformLocation(m_shaderProgram, "u_monitorResolution");
    m_attribLocationMousePos = glGetUniformLocation(m_shaderProgram, "u_mousePos");
    m_attribLocationMouseUV = glGetUniformLocation(m_shaderProgram, "u_mouseUV");
    m_attribLocationOrigin = glGetUniformLocation(m_shaderProgram, "u_origin");
    m_attribLocationProjMtx = glGetUniformLocation(m_shaderProgram, "u_projMatrix");
    m_attribLocationReadColor = glGetUniformLocation(m_shaderProgram, "u_readColor");
    m_attribLocationReadHeatmap = glGetUniformLocation(m_shaderProgram, "u_readHeatmap");
    m_attribLocationReadHighlight = glGetUniformLocation(m_shaderProgram, "u_readHighlight");
    m_attribLocationResolution = glGetUniformLocation(m_shaderProgram, "u_resolution");
    m_attribLocationTex = glGetUniformLocation(m_shaderProgram, "u_vramTexture");
    m_attribLocationVtxPos = glGetAttribLocation(m_shaderProgram, "i_position");
    m_attribLocationVtxUV = glGetAttribLocation(m_shaderProgram, "i_texUV");
    m_attribLocationWrittenColor = glGetUniformLocation(m_shaderProgram, "u_writtenColor");
    m_attribLocationWrittenHeatmap = glGetUniformLocation(m_shaderProgram, "u_writtenHeatmap");
    m_attribLocationWrittenHighlight = glGetUniformLocation(m_shaderProgram, "u_writtenHighlight");
}

PCSX::Widgets::VRAMViewer::VRAMViewer(bool &show) : m_show(show), m_listener(g_system->m_eventBus) {
    m_editor.setText(s_defaultVertexShader, s_defaultPixelShader, "");
    m_listener.listen<PCSX::Events::GUI::SelectClut>([this](auto event) {
        if (m_hasClut) {
            m_clut.x = event.x / 1024.0f;
            m_clut.y = event.y / 512.0f;
        }
    });
    m_listener.listen<PCSX::Events::GUI::VRAMFocus>([this](auto event) {
        if (!m_isMain) return;
        bool changed = false;
        switch (event.vramMode) {
            case PCSX::Events::GUI::VRAMFocus::VRAM_4BITS:
                if (m_vramMode != VRAM_4BITS) {
                    m_vramMode = VRAM_4BITS;
                    changed = true;
                }
                break;
            case PCSX::Events::GUI::VRAMFocus::VRAM_8BITS:
                if (m_vramMode != VRAM_8BITS) {
                    m_vramMode = VRAM_8BITS;
                    changed = true;
                }
                break;
            case PCSX::Events::GUI::VRAMFocus::VRAM_16BITS:
                if (m_vramMode != VRAM_16BITS) {
                    m_vramMode = VRAM_16BITS;
                    changed = true;
                }
                break;
            case PCSX::Events::GUI::VRAMFocus::VRAM_24BITS:
                if (m_vramMode != VRAM_24BITS) {
                    m_vramMode = VRAM_24BITS;
                    changed = true;
                }
                break;
        }
        if (changed) modeChanged();
        focusOn({float(event.x1), float(event.y1)}, {float(event.x2), float(event.y2)});
    });
}

void PCSX::Widgets::VRAMViewer::drawVRAM(GUI *gui, GLuint textureID) {
    if (!m_shaderProgram) {
        compileShader(gui);
    }
    m_textureID = textureID;
    m_resolution = ImGui::GetContentRegionAvail();
    m_origin = ImGui::GetCursorScreenPos();
    auto viewport = ImGui::GetWindowViewport();
    auto monitor = ImGui::GetViewportPlatformMonitor(viewport);
    m_monitorResolution = monitor->MainSize;
    m_monitorPosition = monitor->MainPos;
    m_monitorDPI = monitor->DpiScale;
    m_mousePos = ImGui::GetIO().MousePos;

    ImDrawList *drawList = ImGui::GetWindowDrawList();
    drawList->AddCallback(
        [](const ImDrawList *parentList, const ImDrawCmd *cmd) {
            VRAMViewer *that = reinterpret_cast<VRAMViewer *>(cmd->UserCallbackData);
            that->imguiCB(parentList, cmd);
        },
        this);

    // TexCoord - (TexturePoint - ResolutionPoint) / dimensions
    // TexCoordTL = 0, 0
    // TexCoordBR = 1, 1
    // ResolutionTL = 0, 0
    // ResolutionBR = m_resolution
    // --> texTL = 0 - (cornerTL - 0) / dimensions = -cornerTL / dimensions
    // --> texBR = 1 - (cornerBR - m_resolution) / dimensions
    ImVec2 dimensions = m_cornerBR - m_cornerTL;
    ImVec2 texTL = ImVec2(0.0f, 0.0f) - m_cornerTL / dimensions;
    ImVec2 texBR = ImVec2(1.0f, 1.0f) - (m_cornerBR - m_resolution) / dimensions;
    ImGui::ImageButton(reinterpret_cast<ImTextureID *>(textureID), m_resolution, texTL, texBR, 0);
    if (m_clutDestination && m_selectingClut) {
        m_clutDestination->m_clut = m_mouseUV;
    }

    bool hovered = m_hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_None);
    if (ImGui::IsItemClicked()) m_selectingClut = false;

    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);

    const auto &io = ImGui::GetIO();

    ImVec2 texSpan = texBR - texTL;
    if (hovered) {
        m_mouseUV = texTL + texSpan * (m_mousePos - m_origin) / m_resolution;
    }

    if (!hovered) {
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
            zoom(step, m_mouseUV);
        }
    } else if (io.MouseDown[2] || (io.MouseDown[0] && io.MouseDown[1])) {
        m_cornerTL += io.MouseDelta;
        m_cornerBR = m_cornerTL + dimensions;
    }
}

void PCSX::Widgets::VRAMViewer::drawEditor(GUI *gui) {
    bool changed = m_editor.draw(gui, _("VRAM Shader Editor"));
    if (!changed) return;
    compileShader(gui);
}

void PCSX::Widgets::VRAMViewer::imguiCB(const ImDrawList *parentList, const ImDrawCmd *cmd) {
    glBindTexture(GL_TEXTURE_2D, m_textureID);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    if (!m_shaderProgram) return;
    GLint imguiProgramID;
    glGetIntegerv(GL_CURRENT_PROGRAM, &imguiProgramID);

    GLint projMatrixLocation = glGetUniformLocation(imguiProgramID, "ProjMtx");

    GLfloat currentProjection[4][4];
    glGetUniformfv(imguiProgramID, projMatrixLocation, &currentProjection[0][0]);

    glUseProgram(m_shaderProgram);

    glUniform1i(m_attribLocation24shift, m_24shift);
    glUniform1i(m_attribLocationAlpha, m_alpha);
    glUniform2f(m_attribLocationClut, m_clut.x, m_clut.y);
    glUniform2f(m_attribLocationCornerBR, m_cornerBR.x, m_cornerBR.y);
    glUniform2f(m_attribLocationCornerTL, m_cornerTL.x, m_cornerTL.y);
    if (!m_hasClut && m_vramMode < 2) {
        glUniform1i(m_attribLocationGreyscale, 1);
    } else {
        glUniform1i(m_attribLocationGreyscale, m_greyscale);
    }
    glUniform1i(m_attribLocationHovered, m_hovered);
    glUniform1i(m_attribLocationMagnify, m_magnify);
    if (m_magnifyAmount < 0.0f) {
        glUniform1f(m_attribLocationMagnifyAmount, -1.0f / m_magnifyAmount);
    } else {
        glUniform1f(m_attribLocationMagnifyAmount, m_magnifyAmount);
    }
    glUniform1f(m_attribLocationMagnifyRadius, m_magnifyRadius);
    glUniform1i(m_attribLocationMode, m_vramMode);
    glUniform1f(m_attribLocationMonitorDPI, m_monitorDPI);
    glUniform2f(m_attribLocationMonitorPosition, m_monitorPosition.x, m_monitorPosition.y);
    glUniform2f(m_attribLocationMonitorResolution, m_monitorResolution.x, m_monitorResolution.y);
    glUniform2f(m_attribLocationMousePos, m_mousePos.x, m_mousePos.y);
    glUniform2f(m_attribLocationMouseUV, m_mouseUV.x, m_mouseUV.y);
    glUniform2f(m_attribLocationOrigin, m_origin.x, m_origin.y);
    glUniformMatrix4fv(m_attribLocationProjMtx, 1, GL_FALSE, &currentProjection[0][0]);
    glUniform4f(m_attribLocationReadColor, m_readColor.x, m_readColor.y, m_readColor.z, m_readColor.w);
    glUniform1i(m_attribLocationReadHeatmap, 2);
    glUniform1i(m_attribLocationReadHighlight, 4);
    glUniform2f(m_attribLocationResolution, m_resolution.x, m_resolution.y);
    glUniform1i(m_attribLocationTex, 0);
    glEnableVertexAttribArray(m_attribLocationVtxPos);
    glVertexAttribPointer(m_attribLocationVtxPos, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, pos));
    glEnableVertexAttribArray(m_attribLocationVtxUV);
    glVertexAttribPointer(m_attribLocationVtxUV, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, uv));
    glUniform4f(m_attribLocationWrittenColor, m_writtenColor.x, m_writtenColor.y, m_writtenColor.z, m_writtenColor.w);
    glUniform1i(m_attribLocationWrittenHeatmap, 1);
    glUniform1i(m_attribLocationWrittenHighlight, 3);

    auto *logger = g_emulator->m_gpuLogger.get();
    glActiveTexture(GL_TEXTURE1);
    logger->bindWrittenHeatmap();
    glActiveTexture(GL_TEXTURE2);
    logger->bindReadHeatmap();
    glActiveTexture(GL_TEXTURE3);
    logger->bindWrittenHighlight();
    glActiveTexture(GL_TEXTURE4);
    logger->bindReadHighlight();
    glActiveTexture(GL_TEXTURE0);
}

void PCSX::Widgets::VRAMViewer::resetView() {
    m_cornerTL = {0.0f, 0.0f};
    m_cornerBR = {512.0f / RATIOS[m_vramMode], 512.0f};
    m_cornerBR *= m_DPI;
    m_magnifyAmount = 5.0f;
    m_magnifyRadius = 150.0f * m_DPI;
}

void PCSX::Widgets::VRAMViewer::draw(GUI *gui, unsigned int VRAMTexture) {
    bool openReadColorPicker = false;
    bool openWrittenColorPicker = false;
    auto flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_MenuBar;
    if (ImGui::Begin(m_title().c_str(), &m_show, flags)) {
        m_DPI = ImGui::GetWindowDpiScale();
        if (!m_firstShown) {
            resetView();
            m_firstShown = true;
        }
        if (ImGui::BeginMenuBar()) {
            if (ImGui::BeginMenu(_("File"))) {
                ImGui::EndMenu();
            }
            ImGui::Separator();
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
                if (m_isMain) {
                    ImGui::Separator();
                    ImGui::MenuItem(_("Show Shader Editor"), nullptr, &m_editor.m_show);
                }
                ImGui::EndMenu();
            }
            if (m_isMain) {
                ImGui::Separator();
                if (ImGui::BeginMenu(_("Configuration"))) {
                    ImGui::MenuItem(_("Select read highlight color"), nullptr, &openReadColorPicker);
                    ImGui::MenuItem(_("Select written highlight color"), nullptr, &openWrittenColorPicker);
                    ImGui::EndMenu();
                }
            }
            ImGui::Separator();
            ImGui::Separator();
            float divisor = m_vramMode == VRAM_4BITS ? 4.0f : m_vramMode == VRAM_8BITS ? 2.0f : 1.0f;
            ImGui::Text("Cursor: %.2f : %.2f", std::floor(m_mouseUV.x * 1024.0f * divisor) / divisor,
                        std::floor(m_mouseUV.y * 512.0f * divisor) / divisor);
            if (m_hasClut) {
                ImGui::Separator();
                ImGui::Text("CLUT: %.0f : %.0f", std::floor(m_clut.x * 1024.0f), std::floor(m_clut.y * 512.0f));
            }
            ImGui::EndMenuBar();
        }
        drawVRAM(gui, VRAMTexture);
    }
    if (openReadColorPicker) {
        ImGui::OpenPopup(_("Read Highlight Color Picker"));
    }
    if (ImGui::BeginPopupModal(_("Read Highlight Color Picker"), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::ColorPicker4(
            "##ReadColorPicker", (float *)&m_readColor,
            ImGuiColorEditFlags_PickerHueWheel | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
        if (ImGui::Button(_("OK"))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    if (openWrittenColorPicker) {
        ImGui::OpenPopup(_("Written Highlight Color Picker"));
    }
    if (ImGui::BeginPopupModal(_("Written Highlight Color Picker"), nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::ColorPicker4(
            "##WrittenColorPicker", (float *)&m_writtenColor,
            ImGuiColorEditFlags_PickerHueWheel | ImGuiColorEditFlags_AlphaBar | ImGuiColorEditFlags_AlphaPreview);
        if (ImGui::Button(_("OK"))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::End();

    if (m_editor.m_show) {
        drawEditor(gui);
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

void PCSX::Widgets::VRAMViewer::moveTo(ImVec2 pos) {
    pos /= {-1024.0, -512.0};
    ImVec2 dimensions = m_cornerBR - m_cornerTL;
    ImVec2 texTL = ImVec2(0.0f, 0.0f) - m_cornerTL / dimensions;
    ImVec2 texBR = ImVec2(1.0f, 1.0f) - (m_cornerBR - m_resolution) / dimensions;
    ImVec2 texSpan = texBR - texTL;

    m_cornerTL = pos * m_resolution / texSpan;
    m_cornerBR = m_cornerTL + dimensions;
}

void PCSX::Widgets::VRAMViewer::focusOn(ImVec2 topLeft, ImVec2 bottomRight) {
    m_cornerTL = {0.0f, 0.0f};
    ImVec2 dimensions = bottomRight - topLeft + ImVec2{1.0f, 1.0f};
    float r = dimensions.y / dimensions.x;
    if (r > 2.0f) {
        dimensions.x = dimensions.y / 2.0f;
    } else {
        dimensions.y = dimensions.x * 2.0f;
    }
    dimensions = m_resolution / dimensions;
    ImGuiHelpers::normalizeDimensions(dimensions, RATIOS[m_vramMode]);
    m_cornerBR = ImVec2(512.0f / RATIOS[m_vramMode], 512.0f) * std::max(dimensions.x, dimensions.y);
    moveTo(topLeft);
    ImVec2 center = (topLeft + (bottomRight - topLeft) / 2) / ImVec2(1024.0f, 512.0f);
    zoom(0.9f, center);
}

void PCSX::Widgets::VRAMViewer::zoom(float factor, ImVec2 centerUV) {
    ImVec2 dimensions = m_cornerBR - m_cornerTL;
    ImVec2 newDimensions = dimensions * factor;
    ImVec2 dimensionsDiff = newDimensions - dimensions;
    m_cornerTL -= dimensionsDiff * centerUV;
    m_cornerBR = m_cornerTL + newDimensions;
}
