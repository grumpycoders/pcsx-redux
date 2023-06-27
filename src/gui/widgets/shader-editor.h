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

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "GL/gl3w.h"
#include "gui/widgets/zep.h"
#include "lua/luawrapper.h"
#include "support/opengl.h"

namespace PCSX {

class GUI;

namespace Widgets {

class ShaderEditor {
  public:
    ShaderEditor(const std::string& base, const std::string_view& dVS, const std::string_view& dPS,
                 const std::string_view& dL);
    ShaderEditor(const std::string& base);
    OpenGL::Status compile(GUI* gui, const std::vector<std::string_view>& mandatoryAttributes = {});
    bool isProgramCompiled() { return m_shaderProgram != 0; }
    GLuint getProgram() { return m_shaderProgram; }

    ~ShaderEditor();

    bool m_show = false;

    void setText(const char* VS, const char* PS, const char* L) {
        m_vertexShaderEditor.setText(VS);
        m_pixelShaderEditor.setText(PS);
        m_luaEditor.setText(L);
    }

    void setDefaults();
    void setFallbacks();
    void init();
    void reset(GUI*);

    bool draw(GUI*, const char* title);
    void renderWithImgui(GUI* gui, ImTextureID textureID, const ImVec2& srcSize, const ImVec2& dstSize);
    void render(GUI*, GLuint textureID, const ImVec2& srcLoc, const ImVec2& srcSize, const ImVec2& dstSize);

    void setConfigure(bool configure = true);
    void configure(GUI*);

  private:
    std::string getVertexText() { return m_vertexShaderEditor.getText(); }
    std::string getPixelText() { return m_pixelShaderEditor.getText(); }
    std::string getLuaText() { return m_luaEditor.getText(); }

    void getRegistry(Lua L);

    void imguiCB(const ImDrawList* parentList, const ImDrawCmd* cmd);

    const std::string m_baseFilename;

    ZepEditor m_vertexShaderEditor = {"VertexShader.vert"};
    ZepEditor m_pixelShaderEditor = {"PixelShader.frag"};
    ZepEditor m_luaEditor = {"LuaInvoker.lua"};
    GLuint m_shaderProgram = 0;
    std::string m_errorMessage;
    std::vector<std::string> m_lastLuaErrors;
    bool m_displayError = false;
    bool m_autocompile = true;
    bool m_autosave = true;
    bool m_showAll = false;
    bool m_setupVAO = true;

    static lua_Number s_index;
    const lua_Number m_index;

    OpenGL::VertexArray m_vao;
    OpenGL::VertexBuffer m_vbo = 0;
    GLint m_imguiProjMtxLoc = -1;  // -1 = not found
    GLint m_shaderProjMtxLoc = -1;
    GLint m_imguiProgram = 0;

    GUI* m_cachedGui = nullptr;

    struct VertexData {
        float positions[2];
        float textures[2];
        float color[4] = {1.0f, 1.0f, 1.0f, 1.0f};
    };

    VertexData m_quadVertices[4];
};

}  // namespace Widgets
}  // namespace PCSX
