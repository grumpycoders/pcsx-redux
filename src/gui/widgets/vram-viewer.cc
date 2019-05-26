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

#include "GL/gl3w.h"

#include "gui/widgets/vram-viewer.h"

#define GL_SHADER_VERSION "#version 300 es\n"

static const GLchar *vertexShader = GL_SHADER_VERSION R"(
precision highp float;
layout (location = 0) in vec2 position;
layout (location = 1) in vec2 texUV;
layout (location = 2) in vec4 color;
uniform mat4 projMatrix;
out vec2 fragUV;
out vec4 fragColor;

void main() {
    fragUV = texUV;
    fragColor = color;
    gl_Position = projMatrix * vec4(position.xy, 0.0f, 1.0f);
}
)";

static const GLchar *pixelShader = GL_SHADER_VERSION R"(
precision highp float;
uniform sampler2D vramTexture;
in vec2 fragUV;
in vec4 fragColor;
layout (location = 0) out vec4 outColor;

void main() {
    outColor = fragColor * texture(vramTexture, fragUV.st);
    outColor.a = 1.0f;
}
)";

static GLuint compileShader(const char *VS, const char *PS) {
    GLuint vertexshader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertexshader, 1, &VS, 0);
    glCompileShader(vertexshader);
    GLint IsCompiled_VS = 0;
    glGetShaderiv(vertexshader, GL_COMPILE_STATUS, &IsCompiled_VS);
    if (IsCompiled_VS == 0) {
        GLint maxLength;
        glGetShaderiv(vertexshader, GL_INFO_LOG_LENGTH, &maxLength);
        char *vertexInfoLog = (char *)malloc(maxLength);

        glGetShaderInfoLog(vertexshader, maxLength, &maxLength, vertexInfoLog);

        SDL_TriggerBreakpoint();
        assert(false);

        free(vertexInfoLog);
    }

    GLuint fragmentshader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fragmentshader, 1, &PS, 0);
    glCompileShader(fragmentshader);
    GLint IsCompiled_PS = 0;
    glGetShaderiv(fragmentshader, GL_COMPILE_STATUS, &IsCompiled_PS);
    if (IsCompiled_PS == 0) {
        GLint maxLength;
        glGetShaderiv(fragmentshader, GL_INFO_LOG_LENGTH, &maxLength);
        char *fragmentInfoLog = (char *)malloc(maxLength);

        glGetShaderInfoLog(fragmentshader, maxLength, &maxLength, fragmentInfoLog);

        SDL_TriggerBreakpoint();
        assert(false);

        free(fragmentInfoLog);
    }

    GLuint shaderprogram = glCreateProgram();
    glAttachShader(shaderprogram, vertexshader);
    glAttachShader(shaderprogram, fragmentshader);

    glLinkProgram(shaderprogram);

    GLint IsLinked = 0;
    glGetProgramiv(shaderprogram, GL_LINK_STATUS, &IsLinked);
    assert(IsLinked);

    return shaderprogram;
}

void PCSX::Widgets::VRAMViewer::init() {
    m_shaderProgram = compileShader(vertexShader, pixelShader);
    m_attribLocationTex = glGetUniformLocation(m_shaderProgram, "vramTexture");
    m_attribLocationProjMtx = glGetUniformLocation(m_shaderProgram, "projMatrix");
    m_attribLocationVtxPos = glGetAttribLocation(m_shaderProgram, "position");
    m_attribLocationVtxUV = glGetAttribLocation(m_shaderProgram, "texUV");
    m_attribLocationVtxColor = glGetAttribLocation(m_shaderProgram, "color");
}

void PCSX::Widgets::VRAMViewer::draw(unsigned int textureId, ImVec2 dimensions) {
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    drawList->AddCallback(imguiCBtrampoline, this);
    ImGui::Image((ImTextureID)textureId, dimensions, ImVec2(0, 0), ImVec2(1, 1));
    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
}

void PCSX::Widgets::VRAMViewer::imguiCBtrampoline(const ImDrawList *parentList, const ImDrawCmd *cmd) {
    VRAMViewer *that = reinterpret_cast<VRAMViewer*>(cmd->UserCallbackData);
    that->imguiCB(parentList, cmd);
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
    glEnableVertexAttribArray(m_attribLocationVtxPos);
    glEnableVertexAttribArray(m_attribLocationVtxUV);
    glEnableVertexAttribArray(m_attribLocationVtxColor);
    glVertexAttribPointer(m_attribLocationVtxPos, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, pos));
    glVertexAttribPointer(m_attribLocationVtxUV, 2, GL_FLOAT, GL_FALSE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, uv));
    glVertexAttribPointer(m_attribLocationVtxColor, 4, GL_UNSIGNED_BYTE, GL_TRUE, sizeof(ImDrawVert),
                          (GLvoid *)IM_OFFSETOF(ImDrawVert, col));
}
