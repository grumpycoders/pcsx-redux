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

#include "core/system.h"
#include "gui/gui.h"
#include "gui/widgets/vram-viewer.h"

#define GL_SHADER_VERSION "#version 300 es\n"

static const GLchar *s_defaultVertexShader = GL_SHADER_VERSION R"(
precision highp float;
in vec2 i_position;
in vec2 i_texUV;
uniform vec2 u_mouseUV;
uniform mat4 u_projMatrix;
uniform vec2 u_cornerTL;
uniform vec2 u_cornerBR;
flat out vec2 mouseUV;
out vec2 fragUV;

void main() {
	vec2 dimensions = u_cornerBR - u_cornerTL;
	vec2 translation = (vec2(0.0f) - u_cornerTL) / dimensions;
	mouseUV = u_mouseUV / dimensions + translation;
    fragUV = i_texUV / dimensions + translation;
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
flat in vec2 mouseUV;
in vec2 fragUV;
out vec4 outColor;
layout(origin_upper_left) in vec4 gl_FragCoord;

uniform bool u_magnify;
uniform float u_magnifyRadius;
uniform float u_magnifyAmount;
const float ridge = 1.5f;

vec4 readTexture(in vec2 pos) {
    if (pos.x > 1.0f) return vec4(0.0f);
    if (pos.y > 1.0f) return vec4(0.0f);
    if (pos.x < 0.0f) return vec4(0.0f);
    if (pos.y < 0.0f) return vec4(0.0f);
    return texture(u_vramTexture, pos);
}

void main() {
    float magnifyAmount = u_magnifyAmount;
    vec2 fragCoord = gl_FragCoord.xy - u_origin;
    vec4 fragColor = readTexture(fragUV.st);
    vec2 magnifyVector = (fragUV.st - mouseUV) / u_magnifyAmount;
    vec4 magnifyColor = readTexture(magnifyVector + mouseUV);

    float blend = u_magnify ?
        smoothstep(u_magnifyRadius + ridge, u_magnifyRadius, distance(fragCoord, u_mousePos)) :
        0.0f;

    outColor = mix(fragColor, magnifyColor, blend);

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
    m_shaderProgram = shaderProgram;
    m_vertexShader = vertexShader;
    m_pixelShader = pixelShader;
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
    if (m_vertexShader) glDeleteShader(m_vertexShader);
    if (m_pixelShader) glDeleteShader(m_pixelShader);
    PCSX::GUI::checkGL();
}

void PCSX::Widgets::VRAMViewer::drawVRAM(unsigned int textureID, ImVec2 dimensions) {
    m_resolution = dimensions;
    dimensions = {m_cornerBR.x - m_cornerTL.x, m_cornerBR.y - m_cornerTL.y};
    ImVec2 translation = {(0.0f - m_cornerTL.x) / dimensions.x, (0.0f - m_cornerTL.y) / dimensions.y};
    m_textureID = textureID;
    ImDrawList *drawList = ImGui::GetWindowDrawList();
    drawList->AddCallback(imguiCBtrampoline, this);
    m_origin = ImGui::GetCursorScreenPos();
    auto mousePos = ImGui::GetIO().MousePos;
    m_mousePos = ImVec2(mousePos.x - m_origin.x, mousePos.y - m_origin.y);
    ImVec2 mouseNorm = ImVec2(m_mousePos.x / m_resolution.x, m_mousePos.y / m_resolution.y);
    ImVec2 mouseUV = {1024.0f * (mouseNorm.x / dimensions.x + translation.x), 512.0f * (mouseNorm.y / dimensions.y + translation.y)};
    ImGui::Image((ImTextureID)textureID, m_resolution, ImVec2(0, 0), ImVec2(1, 1));
    m_hovered = ImGui::IsItemHovered(ImGuiHoveredFlags_None);
    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
    ImGui::Text(_("Cursor location: (%3.0f, %3.0f)"), mouseUV.x, mouseUV.y);
    const auto &io = ImGui::GetIO();
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
            ImVec2 newDimensions = {dimensions.x * step, dimensions.y * step};
            if (newDimensions.x <= 1.0f) newDimensions.x = 1.0f;
            if (newDimensions.y <= 1.0f) newDimensions.y = 1.0f;
            ImVec2 dimensionsDiff = {newDimensions.x - dimensions.x, newDimensions.y - dimensions.y};
            dimensions = newDimensions;
            m_cornerTL.x -= dimensionsDiff.x * mouseNorm.x;
            m_cornerTL.y -= dimensionsDiff.y * mouseNorm.y;
            if (m_cornerTL.x >= 0.0f) m_cornerTL.x = 0.0f;
            if (m_cornerTL.y >= 0.0f) m_cornerTL.y = 0.0f;
            m_cornerBR.x = m_cornerTL.x + dimensions.x;
            m_cornerBR.y = m_cornerTL.y + dimensions.y;
            if (m_cornerBR.x <= 1.0f) {
                m_cornerBR.x = 1.0f;
                m_cornerTL.x = m_cornerBR.x - dimensions.x;
            }
            if (m_cornerBR.y <= 1.0f) {
                m_cornerBR.y = 1.0f;
                m_cornerTL.y = m_cornerBR.y - dimensions.y;
            }
        }
    } else if (io.MouseDown[2]) {
        ImVec2 dimensions = {m_cornerBR.x - m_cornerTL.x, m_cornerBR.y - m_cornerTL.y};
        ImVec2 mouseDeltaNorm = {io.MouseDelta.x / m_resolution.x, io.MouseDelta.y / m_resolution.y};
        m_cornerTL.x += mouseDeltaNorm.x;
        m_cornerTL.y += mouseDeltaNorm.y;
        if (m_cornerTL.x >= 0.0f) m_cornerTL.x = 0.0f;
        if (m_cornerTL.y >= 0.0f) m_cornerTL.y = 0.0f;
        m_cornerBR.x = m_cornerTL.x + dimensions.x;
        m_cornerBR.y = m_cornerTL.y + dimensions.y;
        if (m_cornerBR.x <= 1.0f) {
            m_cornerBR.x = 1.0f;
            m_cornerTL.x = m_cornerBR.x - dimensions.x;
        }
        if (m_cornerBR.y <= 1.0f) {
            m_cornerBR.y = 1.0f;
            m_cornerTL.y = m_cornerBR.y - dimensions.y;
        }
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
    ImVec2 mouseUV = ImVec2(m_mousePos.x / m_resolution.x, m_mousePos.y / m_resolution.y);
    glUniform2f(m_attribLocationMouseUV, mouseUV.x, mouseUV.y);
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
