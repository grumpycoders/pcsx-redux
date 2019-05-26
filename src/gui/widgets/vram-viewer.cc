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

#include "gui/widgets/vram-viewer.h"

#define GL_SHADER_VERSION "#version 300 es\n"

static const GLchar *vertexShader = GL_SHADER_VERSION R"(
precision highp float;
in vec2 position;
in vec2 texUV;
in vec4 color;
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
out vec4 outColor;

void main() {
    outColor = fragColor * texture(vramTexture, fragUV.st);
    outColor.a = 1.0f;
}
)";

static std::pair<GLuint, std::string> compileShader(const char *VS, const char *PS) {
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

        std::string error = log;

        free(log);
        glDeleteShader(vertexShader);

        return std::make_pair(0, error);
    }

    GLuint fragmentShader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fragmentShader, 1, &PS, 0);
    glCompileShader(fragmentShader);

    glGetShaderiv(fragmentShader, GL_COMPILE_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetShaderiv(fragmentShader, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);

        glGetShaderInfoLog(fragmentShader, maxLength, &maxLength, log);

        std::string error = log;

        free(log);
        glDeleteShader(vertexShader);
        glDeleteShader(fragmentShader);

        return std::make_pair(0, error);
    }

    GLuint shaderProgram = glCreateProgram();
    glAttachShader(shaderProgram, vertexShader);
    glAttachShader(shaderProgram, fragmentShader);

    glLinkProgram(shaderProgram);

    glGetProgramiv(shaderProgram, GL_LINK_STATUS, &status);
    if (status == 0) {
        GLint maxLength;
        glGetProgramiv(shaderProgram, GL_INFO_LOG_LENGTH, &maxLength);
        char *log = (char *)malloc(maxLength);

        glGetProgramInfoLog(shaderProgram, maxLength, &maxLength, log);

        std::string error = log;

        free(log);
        glDeleteProgram(shaderProgram);
        glDeleteShader(vertexShader);
        glDeleteShader(fragmentShader);

        return std::make_pair(0, error);
    }

    return std::make_pair(shaderProgram, "");
}

void PCSX::Widgets::VRAMViewer::init() {
    std::string error;
    std::tie(m_shaderProgram, error) = compileShader(vertexShader, pixelShader);
    SDL_assert(m_shaderProgram);
    m_attribLocationTex = glGetUniformLocation(m_shaderProgram, "vramTexture");
    m_attribLocationProjMtx = glGetUniformLocation(m_shaderProgram, "projMatrix");
    m_attribLocationVtxPos = glGetAttribLocation(m_shaderProgram, "position");
    m_attribLocationVtxUV = glGetAttribLocation(m_shaderProgram, "texUV");
    m_attribLocationVtxColor = glGetAttribLocation(m_shaderProgram, "color");
}

void PCSX::Widgets::VRAMViewer::draw(unsigned int textureID, ImVec2 dimensions) {
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    drawList->AddCallback(imguiCBtrampoline, this);
    ImGui::Image((ImTextureID)textureID, dimensions, ImVec2(0, 0), ImVec2(1, 1));
    drawList->AddCallback(ImDrawCallback_ResetRenderState, nullptr);
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
