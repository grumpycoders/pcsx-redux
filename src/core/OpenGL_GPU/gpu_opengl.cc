/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include "gpu_opengl.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <stdexcept>

#include "core/debug.h"
#include "core/psxemulator.h"
#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "tracy/Tracy.hpp"

std::unique_ptr<PCSX::GPU> PCSX::GPU::getOpenGL() { return std::unique_ptr<PCSX::GPU>(new PCSX::OpenGL_GPU()); }

void PCSX::OpenGL_GPU::resetBackend() {
    m_gpustat = 0x14802000;

    m_lastTransparency = Transparency::Opaque;
    m_lastBlendingMode = -1;
    m_drawMode = 0;
    m_rectTexpage = 0;
    m_vertexCount = 0;
    m_syncVRAM = true;
    m_display.reset();

    m_drawAreaLeft = m_drawAreaTop = 0;
    m_drawAreaBottom = vramHeight;
    m_drawAreaRight = vramWidth;
    updateDrawArea();

    m_drawingOffset = OpenGL::ivec2(0, 0);

    m_program.use();
    setDrawOffset(0x00000000);
    setTexWindowUnchecked(0x00000000);
    setBlendFactors(0.0, 0.0);
    setDisplayEnable(false);

    clearVRAM();
}

void PCSX::OpenGL_GPU::clearVRAM(float r, float g, float b, float a) {
    const auto oldFBO = OpenGL::getDrawFramebuffer();
    const auto oldScissor = OpenGL::scissorEnabled();

    m_fbo.bind(OpenGL::DrawFramebuffer);
    OpenGL::disableScissor();
    OpenGL::setClearColor(r, g, b, a);
    OpenGL::clearColor();
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, oldFBO);

    if (oldScissor) OpenGL::enableScissor();
}

void PCSX::OpenGL_GPU::clearVRAM() { clearVRAM(0.f, 0.f, 0.f, 1.f); }

// Do not forget to call this with an active OpenGL context.
int PCSX::OpenGL_GPU::initBackend(UI *ui) {
    m_gui = dynamic_cast<GUI *>(ui);
    // Reserve some size for vertices & vram transfers to avoid dynamic allocations later.
    m_vertices.resize(vertexBufferSize);

    m_vbo.createFixedSize(sizeof(Vertex) * vertexBufferSize, GL_STREAM_DRAW);
    m_vbo.bind();
    m_vao.create();
    m_vao.bind();

    // Position (x and y coord) attribute. Signed 11-bit numbers
    m_vao.setAttributeInt<GLint>(0, 2, sizeof(Vertex), offsetof(Vertex, positions));
    m_vao.enableAttribute(0);
    // Colour attribute
    m_vao.setAttributeInt<GLuint>(1, 1, sizeof(Vertex), offsetof(Vertex, colour));
    m_vao.enableAttribute(1);
    // CLUT attribute
    m_vao.setAttributeInt<GLushort>(2, 1, sizeof(Vertex), offsetof(Vertex, clut));
    m_vao.enableAttribute(2);
    // Texpage attribute
    m_vao.setAttributeInt<GLushort>(3, 1, sizeof(Vertex), offsetof(Vertex, texpage));
    m_vao.enableAttribute(3);
    // UV attribute
    m_vao.setAttributeFloat<GLushort>(4, 2, sizeof(Vertex), offsetof(Vertex, uv));
    m_vao.enableAttribute(4);

    // Make VRAM texture and attach it to draw frambuffer
    const int msaaSampleCount = g_emulator->settings.get<Emulator::SettingMSAA>();
    if (msaaSampleCount > 1 && glTexStorage2DMultisample != nullptr) {
        m_vramTexture.createMSAA(vramWidth, vramHeight, GL_RGBA8, msaaSampleCount);
        m_fbo.createWithTextureMSAA(m_vramTexture);

        m_vramTextureNoMSAA.create(vramWidth, vramHeight, GL_RGBA8);
        m_fboNoMSAA.createWithTexture(m_vramTextureNoMSAA);
        m_multisampled = true;
    } else {
        m_vramTexture.create(vramWidth, vramHeight, GL_RGBA8);
        m_fbo.createWithTexture(m_vramTexture);
        m_multisampled = false;
    }

    m_sampleTexture.create(vramWidth, vramHeight, GL_RGBA8);

    if (glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        throw std::runtime_error("Non-complete framebuffer");
    }

    // Create a plain black texture for when the display is disabled
    // Since GL can automatically repeat textures for us, we can create a tiny texture for this
    OpenGL::Framebuffer dummyFBO;
    m_blankTexture.create(8, 8, GL_RGBA8);
    dummyFBO.createWithDrawTexture(m_blankTexture);  // Create FBO and bind our texture to it
    dummyFBO.bind(OpenGL::DrawFramebuffer);

    // Clear the texture and remove FBO
    OpenGL::setViewport(8, 8);
    OpenGL::setClearColor(0.0, 0.0, 0.0, 1.0);
    OpenGL::clearColor();
    OpenGL::bindScreenFramebuffer();

    // Without manually setting alignment, texture uploads in eg the BIOS will break if the width/x coord are odd
    // TODO: Find efficient method to handle this
    glPixelStorei(GL_UNPACK_ALIGNMENT, 2);
    glPixelStorei(GL_PACK_ALIGNMENT, 2);

    static const char *vertSource = R"(
        #version 330 core

        // inPos: The vertex position.
        // inColor: The colour in BGR888. Top 8 bits are garbage and are trimmed by the vertex shader to conserve CPU time
        // inClut: The CLUT (palette) for textured primitives
        // inTexpage: The texpage. We use bit 15 for indicating an untextured primitive (1 = untextured). This
        // lets us batch untextured and textured primitives together. Bit 15 is unused by hardware, so this is a possible optimization
        // inUV: The UVs (texture coordinates) for textured primitives

        layout (location = 0) in ivec2 inPos;
        layout (location = 1) in uint inColor;
        layout (location = 2) in int inClut;
        layout (location = 3) in int inTexpage;
        layout (location = 4) in vec2 inUV;

        out vec4 vertexColor;
        out vec2 texCoords;
        flat out ivec2 clutBase;
        flat out ivec2 texpageBase;
        flat out int texMode;

        // We always apply a 0.5 offset in addition to the drawing offsets, to cover up OpenGL inaccuracies
        uniform vec2 u_vertexOffsets = vec2(+0.5, -0.5);

        void main() {
           // Normalize coords to [0, 2]
           float x = float(inPos.x);
           float y = float(inPos.y);
           float xx = (x + u_vertexOffsets.x) / 512.0;
           float yy = (y + u_vertexOffsets.y) / 256;

           // Normalize to [-1, 1]
           xx -= 1.0;
           yy -= 1.0;

           float red = float(inColor & 0xffu);
           float green = float((inColor >> 8u) & 0xffu);
           float blue = float((inColor >> 16u) & 0xffu);
           vec3 color = vec3(red, green, blue);

           gl_Position = vec4(xx, yy, 1.0, 1.0);
           vertexColor = vec4(color / 255.0, 1.0);

           if ((inTexpage & 0x8000) != 0) { // Untextured primitive
               texMode = 4;
           } else {
               texMode = (inTexpage >> 7) & 3;
               texCoords = inUV;
               texpageBase = ivec2((inTexpage & 0xf) * 64, ((inTexpage >> 4) & 0x1) * 256);
               clutBase = ivec2((inClut & 0x3f) * 16, inClut >> 6);
           }
        }
    )";

    static const char *fragSource = R"(
        #version 330 core
        in vec4 vertexColor;
        in vec2 texCoords;
        flat in ivec2 clutBase;
        flat in ivec2 texpageBase;
        flat in int texMode;

        // We use dual-source blending in order to emulate the fact that the GPU can enable blending per-pixel
        // FragColor: The colour of the pixel before alpha blending comes into play
        // BlendColor: Contains blending coefficients
        layout(location = 0, index = 0) out vec4 FragColor;
        layout(location = 0, index = 1) out vec4 BlendColor;

        // Tex window uniform format
        // x, y components: masks to & coords with
        // z, w components: masks to | coords with
        uniform ivec4 u_texWindow;
        uniform sampler2D u_vramTex;
        uniform vec4 u_blendFactors;
        uniform vec4 u_blendFactorsIfOpaque = vec4(1.0, 1.0, 1.0, 0.0);

        int floatToU5(float f) {
            return int(floor(f * 31.0 + 0.5));
        }

        vec4 sampleVRAM(ivec2 coords) {
            coords &= ivec2(1023, 511); // Out-of-bounds VRAM accesses wrap
            return texelFetch(u_vramTex, coords, 0);
        }

        int sample16(ivec2 coords) {
            vec4 colour = sampleVRAM(coords);
            int r = floatToU5(colour.r);
            int g = floatToU5(colour.g);
            int b = floatToU5(colour.b);
            int msb = int(ceil(colour.a)) << 15;
            return r | (g << 5) | (b << 10) | msb;
        }

        // Apply texture blending
            // Formula for RGB8 colours: col1 * col2 / 128
        vec4 texBlend(vec4 colour1, vec4 colour2) {
            vec4 ret = (colour1 * colour2) / (128.0 / 255.0);
            ret.a = 1.0;
            return ret;
        }

        void main() {
           if (texMode == 4) { // Untextured primitive
               FragColor = vertexColor;
               BlendColor = u_blendFactors;
               return;
           }

           // Fix up UVs and apply texture window
           ivec2 UV = ivec2(floor(texCoords + vec2(0.0001, 0.0001))) & ivec2(0xff);
           UV = (UV & u_texWindow.xy) | u_texWindow.zw;

           if (texMode == 0) { // 4bpp texture
               ivec2 texelCoord = ivec2(UV.x >> 2, UV.y) + texpageBase;

               int sample = sample16(texelCoord);
               int shift = (UV.x & 3) << 2;
               int clutIndex = (sample >> shift) & 0xf;

               ivec2 sampleCoords = ivec2(clutBase.x + clutIndex, clutBase.y);
               FragColor = texelFetch(u_vramTex, sampleCoords, 0);

               if (FragColor.rgb == vec3(0.0, 0.0, 0.0)) discard;
               BlendColor = FragColor.a >= 0.5 ? u_blendFactors : u_blendFactorsIfOpaque;
               FragColor = texBlend(FragColor, vertexColor);
           } else if (texMode == 1) { // 8bpp texture
               ivec2 texelCoord = ivec2(UV.x >> 1, UV.y) + texpageBase;

               int sample = sample16(texelCoord);
               int shift = (UV.x & 1) << 3;
               int clutIndex = (sample >> shift) & 0xff;

               ivec2 sampleCoords = ivec2(clutBase.x + clutIndex, clutBase.y);
               FragColor = texelFetch(u_vramTex, sampleCoords, 0);

               if (FragColor.rgb == vec3(0.0, 0.0, 0.0)) discard;
               BlendColor = FragColor.a >= 0.5 ? u_blendFactors : u_blendFactorsIfOpaque;
               FragColor = texBlend(FragColor, vertexColor);
           } else { // Texture depth 2 and 3 both indicate 16bpp textures
               ivec2 texelCoord = UV + texpageBase;
               FragColor = sampleVRAM(texelCoord);

               if (FragColor.rgb == vec3(0.0, 0.0, 0.0)) discard;
               FragColor = texBlend(FragColor, vertexColor);
               BlendColor = u_blendFactors;
           }
        }
    )";

    m_shaderEditor.init();
    m_shaderEditor.reset(m_gui);
    m_shaderEditor.setText(vertSource, fragSource, "");
    auto status = m_shaderEditor.compile(m_gui);
    if (!status.isOk()) return -1;
    m_program.setProgram(m_shaderEditor.getProgram());

    m_program.use();
    m_drawingOffsetLoc = OpenGL::uniformLocation(m_program, "u_vertexOffsets");
    m_texWindowLoc = OpenGL::uniformLocation(m_program, "u_texWindow");
    m_blendFactorsLoc = OpenGL::uniformLocation(m_program, "u_blendFactors");
    m_blendFactorsIfOpaqueLoc = OpenGL::uniformLocation(m_program, "u_blendFactorsIfOpaque");

    const auto vramSamplerLoc = OpenGL::uniformLocation(m_program, "u_vramTex");
    glUniform1i(vramSamplerLoc, 0);  // Make the fragment shader read from currently binded texture

    m_vramTexture24.create(1024, 512, GL_RGBA8);
    m_fbo24.createWithDrawTexture(m_vramTexture24);
    m_shaderEditor24.init();
    m_shaderEditor24.reset(m_gui);
    m_shaderEditor24.setDefaults();
    m_shaderEditor24.setText(R"(#version 330 core

precision highp float;
layout (location = 0) in vec2 Position;
layout (location = 1) in vec2 UV;
layout (location = 2) in vec4 Color;
out vec2 Frag_UV;
out vec4 Frag_Color;
void main() {
    Frag_UV = UV;
    Frag_Color = Color;
    gl_Position = vec4(Position.xy, 0, 1);
}
)",
                             R"(#version 330 core

precision highp float;
uniform sampler2D u_vramTexture;
in vec2 Frag_UV;
in vec4 Frag_Color;
layout (location = 0) out vec4 Out_Color;

uniform int u_24shift = 0;

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

    return ret;
}

void main() {
    Out_Color = readTexture(Frag_UV.st);
    Out_Color.a = 1.0;
}
)",
                             R"(
local loc24shift = gl.glGetUniformLocation(shaderProgramID, 'u_24shift')

function BindAttributes(textureID, shaderProgramID, srcLocX, srcLocY, srcSizeX, srcSizeY, dstSizeX, dstSizeY, shift)
    gl.glUniform1i(loc24shift, shift)
end
)");
    status = m_shaderEditor24.compile(m_gui);
    if (!status.isOk()) return -1;

    reset();
    setOpenGLContext();
    return 0;
}

void PCSX::OpenGL_GPU::setLinearFiltering() {
    auto setting = g_emulator->settings.get<Emulator::SettingLinearFiltering>().value;
    const auto filter = setting ? GL_LINEAR : GL_NEAREST;
    const auto tex = getVRAMTexture();

    glBindTexture(GL_TEXTURE_2D, tex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);
    // This function is used for texture initialization so might as well define our wrapping rules too
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    m_display.setLinearFiltering();
}

int PCSX::OpenGL_GPU::shutdown() { return 0; }

uint32_t PCSX::OpenGL_GPU::readStatusInternal() {
    return 0b01011110100000000000000000000000;
    // return m_gpustat;
}

bool PCSX::OpenGL_GPU::configure() {
    bool changed = false;

    if (m_shaderEditor.m_show && m_shaderEditor.draw(m_gui, "Hardware renderer shader editor")) {
        const auto status = m_shaderEditor.compile(m_gui);
        if (status.isOk()) {
            m_program.setProgram(m_shaderEditor.getProgram());
            const auto lastProgram = OpenGL::getProgram();

            m_program.use();
            m_drawingOffsetLoc = OpenGL::uniformLocation(m_program, "u_vertexOffsets");
            m_texWindowLoc = OpenGL::uniformLocation(m_program, "u_texWindow");
            m_blendFactorsLoc = OpenGL::uniformLocation(m_program, "u_blendFactors");
            m_blendFactorsIfOpaqueLoc = OpenGL::uniformLocation(m_program, "u_blendFactorsIfOpaque");

            const auto vramSamplerLoc = OpenGL::uniformLocation(m_program, "u_vramTex");
            glUniform1i(vramSamplerLoc, 0);  // Make the fragment shader read from currently bound texture
            glUniform4f(m_blendFactorsIfOpaqueLoc, 1.0, 1.0, 1.0, 0.0);
            glUniform4f(m_blendFactorsLoc, m_blendFactors.x(), m_blendFactors.x(), m_blendFactors.x(),
                        m_blendFactors.y());

            setDrawOffset(m_lastDrawOffsetSetting);
            setTexWindowUnchecked(m_lastTexwindowSetting);
            glUseProgram(lastProgram);
        }
    }

    if (ImGui::Begin(_("OpenGL GPU configuration"), &m_showCfg)) {
        static const char *polygonModeNames[] = {"Fill polygons", "Wireframe", "Vertices only"};
        constexpr OpenGL::FillMode polygonModes[] = {OpenGL::FillPoly, OpenGL::DrawWire, OpenGL::DrawPoints};

        if (ImGui::BeginCombo(_("Polygon rendering mode"), polygonModeNames[m_polygonModeIndex])) {
            for (auto i = 0; i < 3; i++) {
                if (ImGui::Selectable(polygonModeNames[i])) {
                    m_polygonMode = polygonModes[i];
                    m_polygonModeIndex = i;
                }
            }
            ImGui::EndCombo();
        }

        int msaaSampleCount = g_emulator->settings.get<Emulator::SettingMSAA>();
        const auto msaaString = msaaSampleCount == 1 ? _("No MSAA") : fmt::format(f_("{}x MSAA"), msaaSampleCount);

        if (ImGui::BeginCombo(_("MSAA"), msaaString.c_str())) {
            const int maxMSAA = OpenGL::maxSamples();

            if (ImGui::Selectable(_("No MSAA"))) {
                g_emulator->settings.get<Emulator::SettingMSAA>() = 1;
                changed = true;
            }

            for (int i = 2; i <= maxMSAA; i *= 2) {
                auto str = std::to_string(i) + "x MSAA";
                if (ImGui::Selectable(str.c_str())) {
                    g_emulator->settings.get<Emulator::SettingMSAA>() = i;
                    changed = true;
                }
            }
            ImGui::EndCombo();
        }

        if (ImGui::Checkbox(_("Use linear filtering"),
                            &g_emulator->settings.get<Emulator::SettingLinearFiltering>().value)) {
            changed = true;
            setLinearFiltering();
        }
        ImGui::Checkbox("Edit OpenGL GPU shaders", &m_shaderEditor.m_show);
        ImGui::End();
    }

    return changed;
}

void PCSX::OpenGL_GPU::debug() {
    if (ImGui::Begin(_("OpenGL GPU Debugger"), &m_showDebug)) {
        const auto width = m_display.size.x();
        const auto height = m_display.size.y();
        const auto startX = m_display.start.x();
        const auto startY = m_display.start.y();

        ImGui::Text(_("Display horizontal range: %d-%d"), startX, startX + width);
        ImGui::Text(_("Display vertical range: %d-%d"), startY, startY + height);
        ImGui::Text(_("Drawing area offset: (%d, %d)"), m_drawingOffset.x(), m_drawingOffset.y());
        ImGui::Text(_("Resolution: %dx%d"), width, height);

        ImGui::ColorEdit3(_("Clear colour"), &m_clearColour[0]);
        if (ImGui::Button(_("Clear VRAM"))) {
            clearVRAM(m_clearColour.r(), m_clearColour.g(), m_clearColour.b());
        }
    }

    ImGui::End();
}

// Called at the start of a UI frame to restore context
void PCSX::OpenGL_GPU::setOpenGLContext() {
    m_vbo.bind();
    m_vao.bind();
    m_fbo.bind(OpenGL::DrawAndReadFramebuffer);
    m_sampleTexture.bind();
    OpenGL::setViewport(m_vramTexture.width(), m_vramTexture.height());
    OpenGL::enableScissor();

    if (m_polygonMode != OpenGL::FillPoly) {
        OpenGL::setFillMode(m_polygonMode);
    }

    m_program.use();
}

void PCSX::OpenGL_GPU::updateDrawArea() {
    renderBatch();
    const int left = m_drawAreaLeft;
    const int width = std::max<int>(m_drawAreaRight - left + 1, 0);
    const int top = m_drawAreaTop;
    const int height = std::max<int>(m_drawAreaBottom - m_drawAreaTop + 1, 0);

    m_scissorBox.x = left;
    m_scissorBox.y = top;
    m_scissorBox.width = width;
    m_scissorBox.height = height;
    setScissorArea();
}

// Set the OpenGL scissor based on our PS1's drawing area.
void PCSX::OpenGL_GPU::setScissorArea() {
    OpenGL::setScissor(m_scissorBox.x, m_scissorBox.y, m_scissorBox.width, m_scissorBox.height);
}

GLuint PCSX::OpenGL_GPU::getVRAMTexture() {
    if (!m_multisampled) {
        return m_vramTexture.handle();
    } else {
        return m_vramTextureNoMSAA.handle();
    }
}

// Called at the end of a frame
void PCSX::OpenGL_GPU::vblank(bool fromGui) {
    renderBatch();

    // Set the fill mode to fill before passing the OpenGL context to the GUI
    if (m_polygonMode != OpenGL::FillPoly) {
        OpenGL::setFillMode(OpenGL::FillPoly);
    }

    // Disable scissor before passing the GPU to the frontend. This is also necessary as scissor testing affects
    // glBlitFramebuffer
    OpenGL::disableScissor();
    if (m_lastTransparency == Transparency::Transparent) {
        m_lastTransparency = Transparency::Opaque;
        m_lastBlendingMode = -1;
        OpenGL::disableBlend();
    }

    GLuint texture;
    if (!m_display.enabled) {
        texture = m_blankTexture.handle();
    } else {
        // We can't draw the MSAA texture directly. So if we're using MSAA, we copy the texture to a non-MSAA texture.
        if (m_multisampled) {
            m_fbo.bind(OpenGL::ReadFramebuffer);
            m_fboNoMSAA.bind(OpenGL::DrawFramebuffer);
            glBlitFramebuffer(0, 0, 1024, 512, 0, 0, 1024, 512, GL_COLOR_BUFFER_BIT, GL_LINEAR);
            texture = m_vramTextureNoMSAA.handle();
        } else {
            texture = m_vramTexture.handle();
        }
    }

    float startX = m_display.startNormalized.x();
    float startY = m_display.startNormalized.y();
    float width = m_display.sizeNormalized.x();
    float height = m_display.sizeNormalized.y();

    if (m_display.info.depth == CtrlDisplayMode::CD_24BITS) {
        m_fbo24.bind(OpenGL::DrawFramebuffer);
        OpenGL::setViewport(1024, 512);
        m_shaderEditor24.render(m_gui, texture, {0, 0}, {1, 1}, {1024, 512}, {lua_Number(m_display.start.x() * 2)});
        texture = m_vramTexture24.handle();
        width *= 1.5f;
    }

    m_gui->setViewport();
    if (!fromGui) m_gui->flip();  // Set up offscreen framebuffer before rendering

    m_gui->m_offscreenShaderEditor.render(m_gui, texture, {startX, startY}, {width, height}, m_gui->getRenderSize());
}

void PCSX::OpenGL_GPU::renderBatch() {
    if (m_vertexCount > 0) {
        if (m_syncVRAM) {
            m_syncVRAM = false;
            glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 0, 0, vramWidth, vramHeight);
        }

        if (m_updateDrawOffset) {
            m_updateDrawOffset = false;
            setDrawOffset(m_lastDrawOffsetSetting);
        }
        m_vbo.bufferVertsSub(&m_vertices[0], m_vertexCount);

        // Special handling if we're using subtractive blending
        if (m_lastBlendingMode == 2) {
            // Draw opaque only
            OpenGL::setBlendEquation(OpenGL::BlendEquation::Add);
            setBlendFactors(0.0, 1.0);
            OpenGL::draw(OpenGL::Triangles, m_vertexCount);

            // Draw transparent only
            OpenGL::setBlendEquation(OpenGL::BlendEquation::ReverseSub, OpenGL::BlendEquation::Add);
            setBlendFactors(1.0, 1.0);
            glUniform4f(m_blendFactorsIfOpaqueLoc, 0.0, 0.0, 0.0, 1.0);
            OpenGL::draw(OpenGL::Triangles, m_vertexCount);

            glUniform4f(m_blendFactorsIfOpaqueLoc, 1.0, 1.0, 1.0, 0.0);
        } else {
            OpenGL::draw(OpenGL::Triangles, m_vertexCount);
        }
        m_vertexCount = 0;
    }
}

void PCSX::OpenGL_GPU::setDisplayEnable(bool enabled) { m_display.enabled = enabled; }

PCSX::Slice PCSX::OpenGL_GPU::getVRAM(Ownership) {
    static constexpr uint32_t texSize = 1024 * 512 * sizeof(uint16_t);
    uint16_t *pixels = (uint16_t *)malloc(texSize);
    glFlush();
    const auto oldTex = OpenGL::getTex2D();
    glBindTexture(GL_TEXTURE_2D, getVRAMTexture());
    glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, pixels);
    glBindTexture(GL_TEXTURE_2D, oldTex);

    Slice slice;
    slice.acquire(pixels, texSize);
    return slice;
}

void PCSX::OpenGL_GPU::partialUpdateVRAM(int x, int y, int w, int h, const uint16_t *pixels,
                                         PartialUpdateVram updateType) {
    renderBatch();

    OpenGL::bindScreenFramebuffer();
    const auto oldTex = updateType == PartialUpdateVram::Asynchronous ? OpenGL::getTex2D() : GLint(-1);
    m_vramTexture.bind();

    glTexSubImage2D(GL_TEXTURE_2D, 0, x, y, w, h, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, pixels);

    if (updateType == PartialUpdateVram::Asynchronous) glBindTexture(GL_TEXTURE_2D, oldTex);
    m_fbo.bind(OpenGL::DrawAndReadFramebuffer);

    m_syncVRAM = true;
}

template <PCSX::OpenGL_GPU::Transparency setting>
void PCSX::OpenGL_GPU::setTransparency() {
    // Check if we had transparency previously disabled and it just got enabled or vice versa
    if (m_lastTransparency != setting) {
        renderBatch();
        if constexpr (setting == Transparency::Opaque) {
            m_lastBlendingMode = -1;
            OpenGL::disableBlend();
        } else {
            OpenGL::enableBlend();
        }

        m_lastTransparency = setting;
    }
}

void PCSX::OpenGL_GPU::setBlendingModeFromTexpage(uint32_t texpage) {
    const auto newBlendingMode = (texpage >> 5) & 3;

    if (m_lastBlendingMode != newBlendingMode) {
        renderBatch();  // This must be executed before we set the new blend mode
        m_lastBlendingMode = newBlendingMode;
        OpenGL::setBlendFactor(GL_SRC1_COLOR, GL_SRC1_ALPHA, GL_ONE, GL_ZERO);

        switch (newBlendingMode) {
            case 0:  // B/2 + F/2
                OpenGL::setBlendEquation(OpenGL::BlendEquation::Add);
                setBlendFactors(0.5, 0.5);
                break;
            case 1:  // B + F
                OpenGL::setBlendEquation(OpenGL::BlendEquation::Add);
                setBlendFactors(1.0, 1.0);
                break;
            case 2:  // B - F. We special handle this in the renderBatch() function
                break;
            case 3:  // B + F/4
                OpenGL::setBlendEquation(OpenGL::BlendEquation::Add);
                setBlendFactors(0.25, 1.0);
                break;
        }
    }
}

void PCSX::OpenGL_GPU::setBlendFactors(float sourceFactor, float destFactor) {
    if (m_blendFactors.x() != sourceFactor || m_blendFactors.y() != destFactor) {
        m_blendFactors.x() = sourceFactor;
        m_blendFactors.y() = destFactor;

        glUniform4f(m_blendFactorsLoc, sourceFactor, sourceFactor, sourceFactor, destFactor);
    }
}

void PCSX::OpenGL_GPU::drawTri(int *x, int *y, uint32_t *colors) {
    maybeRenderBatch<3>();

    m_vertices[m_vertexCount++] = Vertex(x[0], y[0], colors[0]);
    m_vertices[m_vertexCount++] = Vertex(x[1], y[1], colors[1]);
    m_vertices[m_vertexCount++] = Vertex(x[2], y[2], colors[2]);
}

void PCSX::OpenGL_GPU::drawTriTextured(int *x, int *y, uint32_t *colors, uint16_t clut, uint16_t texpage, unsigned *u,
                                       unsigned *v) {
    maybeRenderBatch<3>();

    m_vertices[m_vertexCount++] = Vertex(x[0], y[0], colors[0], clut, texpage, u[0], v[0]);
    m_vertices[m_vertexCount++] = Vertex(x[1], y[1], colors[1], clut, texpage, u[1], v[1]);
    m_vertices[m_vertexCount++] = Vertex(x[2], y[2], colors[2], clut, texpage, u[2], v[2]);
}

void PCSX::OpenGL_GPU::drawRect(int x, int y, int w, int h, uint32_t color) {
    maybeRenderBatch<6>();
    m_vertices[m_vertexCount++] = Vertex(x, y, color);
    m_vertices[m_vertexCount++] = Vertex(x + w, y, color);
    m_vertices[m_vertexCount++] = Vertex(x + w, y + h, color);
    m_vertices[m_vertexCount++] = Vertex(x + w, y + h, color);
    m_vertices[m_vertexCount++] = Vertex(x, y + h, color);
    m_vertices[m_vertexCount++] = Vertex(x, y, color);
}

void PCSX::OpenGL_GPU::drawRectTextured(int x, int y, int w, int h, uint32_t color, uint16_t clut, unsigned u,
                                        unsigned v) {
    maybeRenderBatch<6>();
    const uint32_t texpage = m_rectTexpage;
    m_vertices[m_vertexCount++] = Vertex(x, y, color, clut, texpage, u, v);
    m_vertices[m_vertexCount++] = Vertex(x + w, y, color, clut, texpage, u + w, v);
    m_vertices[m_vertexCount++] = Vertex(x + w, y + h, color, clut, texpage, u + w, v + h);
    m_vertices[m_vertexCount++] = Vertex(x + w, y + h, color, clut, texpage, u + w, v + h);
    m_vertices[m_vertexCount++] = Vertex(x, y + h, color, clut, texpage, u, v + h);
    m_vertices[m_vertexCount++] = Vertex(x, y, color, clut, texpage, u, v);
}

void PCSX::OpenGL_GPU::drawLine(int x1, int y1, uint32_t color1, int x2, int y2, uint32_t color2) {
    maybeRenderBatch<6>();

    const int32_t dx = x2 - x1;
    const int32_t dy = y2 - y1;

    const auto absDx = std::abs(dx);
    const auto absDy = std::abs(dy);

    // Both vertices coincide, render 1x1 rectangle with the colour and coords of v1
    if (dx == 0 && dy == 0) {
        m_vertices[m_vertexCount++] = Vertex(x1, y1, color1);
        m_vertices[m_vertexCount++] = Vertex(x1 + 1, y1, color1);
        m_vertices[m_vertexCount++] = Vertex(x1 + 1, y1 + 1, color1);

        m_vertices[m_vertexCount++] = Vertex(x1 + 1, y1 + 1, color1);
        m_vertices[m_vertexCount++] = Vertex(x1, y1 + 1, color1);
        m_vertices[m_vertexCount++] = Vertex(x1, y1, color1);
    } else {
        int xOffset, yOffset;
        if (absDx > absDy) {  // x-major line
            xOffset = 0;
            yOffset = 1;

            // Align line depending on whether dx is positive or not
            dx > 0 ? x2++ : x1++;
        } else {  // y-major line
            xOffset = 1;
            yOffset = 0;

            // Align line depending on whether dy is positive or not
            dy > 0 ? y2++ : y1++;
        }

        m_vertices[m_vertexCount++] = Vertex(x1, y1, color1);
        m_vertices[m_vertexCount++] = Vertex(x2, y2, color2);
        m_vertices[m_vertexCount++] = Vertex(x2 + xOffset, y2 + yOffset, color2);

        m_vertices[m_vertexCount++] = Vertex(x2 + xOffset, y2 + yOffset, color2);
        m_vertices[m_vertexCount++] = Vertex(x1 + xOffset, y1 + yOffset, color1);
        m_vertices[m_vertexCount++] = Vertex(x1, y1, color1);
    }
}

void PCSX::OpenGL_GPU::write0(ClearCache *) {
    renderBatch();
    m_syncVRAM = true;
}

void PCSX::OpenGL_GPU::write0(TPage *prim) { m_rectTexpage = prim->raw; }

// Set texture window, regardless of whether the window config changed
void PCSX::OpenGL_GPU::setTexWindowUnchecked(uint32_t cmd) {
    renderBatch();
    m_lastTexwindowSetting = cmd & 0xfffff;  // Only keep bottom 20 bits

    const uint32_t maskX = (cmd & 0x1f) * 8;          // Window mask x in 8 pixel steps
    const uint32_t maskY = ((cmd >> 5) & 0x1f) * 8;   // Window mask y in 8 pixel steps
    const uint32_t offsX = ((cmd >> 10) & 0x1f) * 8;  // Window offset x in 8 pixel steps
    const uint32_t offsY = ((cmd >> 15) & 0x1f) * 8;  // Window offset y in 8 pixel steps

    // Upload data to GPU
    glUniform4i(m_texWindowLoc, ~maskX, ~maskY, offsX & maskX, offsY & maskY);
}

// Set texture window, provided the window config actually changed
void PCSX::OpenGL_GPU::setTexWindow(uint32_t cmd) {
    cmd &= 0xfffff;  // Only keep bottom 20 bits
    if (m_lastTexwindowSetting != cmd) {
        setTexWindowUnchecked(cmd);
    }
}

void PCSX::OpenGL_GPU::write0(TWindow *prim) { setTexWindow(prim->raw); }

void PCSX::OpenGL_GPU::write0(MaskBit *) {}

void PCSX::OpenGL_GPU::write0(DrawingAreaStart *prim) {
    m_drawAreaLeft = prim->x;
    m_drawAreaTop = prim->y;
    updateDrawArea();
}

void PCSX::OpenGL_GPU::write0(DrawingAreaEnd *prim) {
    m_drawAreaRight = prim->x;
    m_drawAreaBottom = prim->y;
    updateDrawArea();
}

void PCSX::OpenGL_GPU::setDrawOffset(uint32_t cmd) {
    m_updateDrawOffset = false;
    m_lastDrawOffsetSetting = cmd & 0x3fffff;  // Discard the bits we don't care about

    // Offset is a signed number in [-1024, 1023]
    const auto offsetX = (int32_t)cmd << 21 >> 21;
    const auto offsetY = (int32_t)cmd << 10 >> 21;

    m_drawingOffset.x() = offsetX;
    m_drawingOffset.y() = offsetY;

    // The 0.5 offsets help fix some holes in rendering, in places like the PS logo
    // TODO: This might not work when upscaling?
    float adjustedOffsets[2] = {static_cast<float>(offsetX) + 0.5f, static_cast<float>(offsetY) - 0.5f};
    glUniform2fv(m_drawingOffsetLoc, 1, adjustedOffsets);
}

void PCSX::OpenGL_GPU::write0(DrawingOffset *prim) {
    renderBatch();
    const uint32_t word = prim->raw & 0x3fffff;

    // Queue a draw offset update if it changed
    if (word != m_lastDrawOffsetSetting) {
        m_updateDrawOffset = true;
        m_lastDrawOffsetSetting = word;
    }
}

void PCSX::OpenGL_GPU::write0(FastFill *prim) {
    renderBatch();
    const auto colour = prim->color;
    const float r = float(colour & 0xff) / 255.f;
    const float g = float((colour >> 8) & 0xff) / 255.f;
    const float b = float((colour >> 16) & 0xff) / 255.f;

    OpenGL::setClearColor(r, g, b, 1.f);
    OpenGL::setScissor(prim->x, prim->y, prim->w, prim->h);
    OpenGL::clearColor();
    setScissorArea();
}

void PCSX::OpenGL_GPU::write0(BlitVramVram *prim) {
    renderBatch();
    OpenGL::disableScissor();  // We disable scissor testing because it affects glBlitFramebuffer

    // TODO: Sanitize this
    const auto srcX = prim->sX;
    const auto srcY = prim->sY;
    const auto destX = prim->dX;
    const auto destY = prim->dY;

    uint32_t width = prim->w;
    uint32_t height = prim->h;

    width = ((width - 1) & 0x3ff) + 1;
    height = ((height - 1) & 0x1ff) + 1;

    glBlitFramebuffer(srcX, srcY, srcX + width, srcY + height, destX, destY, destX + width, destY + height,
                      GL_COLOR_BUFFER_BIT, GL_NEAREST);
    OpenGL::enableScissor();
}

template <PCSX::GPU::Shading shading, PCSX::GPU::Shape shape, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend,
          PCSX::GPU::Modulation modulation>
void PCSX::OpenGL_GPU::polyExec(Poly<shading, shape, textured, blend, modulation> *prim) {
    if constexpr (blend == Blend::Off) {
        setTransparency<Transparency::Opaque>();
    } else if constexpr (blend == Blend::Semi) {
        setTransparency<Transparency::Transparent>();
    }
    if constexpr (textured == Textured::No) {
        if constexpr (blend == Blend::Semi) {
            setBlendingModeFromTexpage(m_rectTexpage);
        }
        drawTri(&prim->x[0], &prim->y[0], &prim->colors[0]);
        if constexpr (shape == Shape::Quad) {
            drawTri(&prim->x[1], &prim->y[1], &prim->colors[1]);
        }
    } else if constexpr (textured == Textured::Yes) {
        if constexpr (blend == Blend::Semi) {
            setBlendingModeFromTexpage(prim->tpage.raw);
        }
        drawTriTextured(&prim->x[0], &prim->y[0], &prim->colors[0], prim->clutraw, prim->tpage.raw, &prim->u[0],
                        &prim->v[0]);
        if constexpr (shape == Shape::Quad) {
            drawTriTextured(&prim->x[1], &prim->y[1], &prim->colors[1], prim->clutraw, prim->tpage.raw, &prim->u[1],
                            &prim->v[1]);
        }
    }
}

template <PCSX::GPU::Shading shading, PCSX::GPU::LineType lineType, PCSX::GPU::Blend blend>
void PCSX::OpenGL_GPU::lineExec(Line<shading, lineType, blend> *prim) {
    auto count = prim->colors.size();

    if constexpr (blend == Blend::Off) {
        setTransparency<Transparency::Opaque>();
    } else if constexpr (blend == Blend::Semi) {
        setTransparency<Transparency::Transparent>();
    }

    for (unsigned i = 1; i < count; i++) {
        auto x0 = prim->x[i - 1];
        auto x1 = prim->x[i];
        auto y0 = prim->y[i - 1];
        auto y1 = prim->y[i];
        auto c0 = prim->colors[i - 1];
        auto c1 = prim->colors[i];

        drawLine(x0, y0, c0, x1, y1, c1);
    }
}

template <PCSX::GPU::Size size, PCSX::GPU::Textured textured, PCSX::GPU::Blend blend, PCSX::GPU::Modulation modulation>
void PCSX::OpenGL_GPU::rectExec(Rect<size, textured, blend, modulation> *prim) {
    if constexpr (blend == Blend::Off) {
        setTransparency<Transparency::Opaque>();
    } else if constexpr (blend == Blend::Semi) {
        setTransparency<Transparency::Transparent>();
        setBlendingModeFromTexpage(m_rectTexpage);
    }
    if constexpr (textured == Textured::No) {
        drawRect(prim->x, prim->y, prim->w, prim->h, prim->color);
    } else if constexpr (textured == Textured::Yes) {
        uint32_t color = 0x808080;
        if constexpr (modulation == Modulation::On) {
            color = prim->color;
        }
        drawRectTextured(prim->x, prim->y, prim->w, prim->h, color, prim->clutraw, prim->u, prim->v);
    }
}

void PCSX::OpenGL_GPU::write1(CtrlReset *) {
    // TODO: This should perform some more operations
    m_display.reset();
    setDisplayEnable(false);
    acknowledgeIRQ1();
}

void PCSX::OpenGL_GPU::write1(CtrlClearFifo *) {}

void PCSX::OpenGL_GPU::write1(CtrlIrqAck *) { acknowledgeIRQ1(); }

void PCSX::OpenGL_GPU::write1(CtrlDisplayEnable *ctrl) { setDisplayEnable(ctrl->enable); }

void PCSX::OpenGL_GPU::write1(CtrlDmaSetting *) {}

void PCSX::OpenGL_GPU::write1(CtrlDisplayStart *ctrl) { m_display.set(ctrl); }
void PCSX::OpenGL_GPU::write1(CtrlHorizontalDisplayRange *ctrl) { m_display.set(ctrl); }
void PCSX::OpenGL_GPU::write1(CtrlVerticalDisplayRange *ctrl) { m_display.set(ctrl); }
void PCSX::OpenGL_GPU::write1(CtrlDisplayMode *ctrl) { m_display.set(ctrl); }

void PCSX::OpenGL_GPU::write1(CtrlQuery *) {}

// clang-format off
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { polyExec(prim); }
void PCSX::OpenGL_GPU::write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *prim) { polyExec(prim); }

void PCSX::OpenGL_GPU::write0(Line<Shading::Flat, LineType::Simple, Blend::Off> *prim) { lineExec(prim); }
void PCSX::OpenGL_GPU::write0(Line<Shading::Flat, LineType::Simple, Blend::Semi> *prim) { lineExec(prim); }
void PCSX::OpenGL_GPU::write0(Line<Shading::Flat, LineType::Poly, Blend::Off> *prim) { lineExec(prim); }
void PCSX::OpenGL_GPU::write0(Line<Shading::Flat, LineType::Poly, Blend::Semi> *prim) { lineExec(prim); }
void PCSX::OpenGL_GPU::write0(Line<Shading::Gouraud, LineType::Simple, Blend::Off> *prim) { lineExec(prim); }
void PCSX::OpenGL_GPU::write0(Line<Shading::Gouraud, LineType::Simple, Blend::Semi> *prim) { lineExec(prim); }
void PCSX::OpenGL_GPU::write0(Line<Shading::Gouraud, LineType::Poly, Blend::Off> *prim) { lineExec(prim); }
void PCSX::OpenGL_GPU::write0(Line<Shading::Gouraud, LineType::Poly, Blend::Semi> *prim) { lineExec(prim); }

void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::Off> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::On> *prim) { rectExec(prim); }
void PCSX::OpenGL_GPU::write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::On> *prim) { rectExec(prim); }
