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

void PCSX::OpenGL_GPU::reset() {
    m_gpustat = 0x14802000;

    m_haveCommand = false;
    m_lastTransparency = Transparency::Opaque;
    m_lastBlendingMode = -1;
    m_readingMode = TransferMode::CommandTransfer;
    m_writingMode = TransferMode::CommandTransfer;
    m_drawMode = 0;
    m_rectTexpage = 0;
    m_remainingWords = 0;
    m_vramReadBufferSize = 0;
    m_FIFOIndex = 0;
    m_vertexCount = 0;
    m_syncVRAM = true;
    m_display.reset();
    m_vramWriteBuffer.clear();

    m_drawAreaLeft = m_drawAreaTop = 0;
    m_drawAreaBottom = vramHeight;
    m_drawAreaRight = vramWidth;
    updateDrawArea();

    m_drawingOffset = OpenGL::ivec2({0, 0});

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
int PCSX::OpenGL_GPU::init() {
    // Reserve some size for vertices & vram transfers to avoid dynamic allocations later.
    m_vertices.resize(vertexBufferSize);
    m_vramReadBuffer.resize(vramWidth * vramHeight);
    m_vramWriteBuffer.reserve(vramWidth * vramHeight);

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

    static const char* vertSource = R"(
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

    static const char* fragSource = R"(
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
               BlendColor = FragColor.a >= 0.5 ? u_blendFactors : vec4(1.0, 1.0, 1.0, 0.0);
               FragColor = texBlend(FragColor, vertexColor);
           } else if (texMode == 1) { // 8bpp texture
               ivec2 texelCoord = ivec2(UV.x >> 1, UV.y) + texpageBase;

               int sample = sample16(texelCoord);
               int shift = (UV.x & 1) << 3;
               int clutIndex = (sample >> shift) & 0xff;

               ivec2 sampleCoords = ivec2(clutBase.x + clutIndex, clutBase.y);
               FragColor = texelFetch(u_vramTex, sampleCoords, 0);

               if (FragColor.rgb == vec3(0.0, 0.0, 0.0)) discard;
               BlendColor = FragColor.a >= 0.5 ? u_blendFactors : vec4(1.0, 1.0, 1.0, 0.0);
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
    m_program.m_handle = m_shaderEditor.compile(m_gui).value();

    m_program.use();
    m_drawingOffsetLoc = OpenGL::uniformLocation(m_program, "u_vertexOffsets");
    m_texWindowLoc = OpenGL::uniformLocation(m_program, "u_texWindow");
    m_blendFactorsLoc = OpenGL::uniformLocation(m_program, "u_blendFactors");

    const auto vramSamplerLoc = OpenGL::uniformLocation(m_program, "u_vramTex");
    glUniform1i(vramSamplerLoc, 0);  // Make the fragment shader read from currently binded texture

    reset();
    initCommands();
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

int PCSX::OpenGL_GPU::shutdown() {
    g_system->printf("Unimplemented OpenGL GPU function: shutdown\n");
    return 0;
}

int PCSX::OpenGL_GPU::open(GUI* gui) {
    m_gui = gui;
    return 0;
}

int PCSX::OpenGL_GPU::close() {
    g_system->printf("Unimplemented OpenGL GPU function: close\n");
    return 0;
}

uint32_t PCSX::OpenGL_GPU::readStatus() {
    return 0b01011110100000000000000000000000;
    // return m_gpustat;
}

uint32_t PCSX::OpenGL_GPU::readData() {
    uint32_t ret;
    readDataMem(&ret, 1);
    return ret;
}

void PCSX::OpenGL_GPU::readDataMem(uint32_t* destination, int size) {
    for (int i = 0; i < size; i++) {
        if (m_readingMode == TransferMode::VRAMTransfer) {
            if (m_vramReadBufferSize == 1) m_readingMode = TransferMode::CommandTransfer;
            *destination++ = m_vramReadBuffer[m_vramReadBufferIndex++];
            m_vramReadBufferSize--;
        } else {
            // g_system->printf("Unimplemented GPUREAD read :(\n");
            return;
        }
    }
}

void PCSX::OpenGL_GPU::writeData(uint32_t value) { writeDataMem(&value, 1); }

void PCSX::OpenGL_GPU::writeDataMem(uint32_t* source, int size) {
    ZoneScoped;  // Let Tracy do its thing

    while (size) {
        const uint32_t word = *source++;  // Fetch word, inc pointer. TODO: Better bounds checking.
        size--;

        if (!m_haveCommand) {
            startGP0Command(word);
        } else {
            if (m_writingMode == TransferMode::VRAMTransfer) {
                if (m_remainingWords == 0) {  // Texture transfer finished
                    renderBatch();
                    m_writingMode = TransferMode::CommandTransfer;
                    m_haveCommand = false;

                    OpenGL::bindScreenFramebuffer();
                    m_vramTexture.bind();
                    glTexSubImage2D(GL_TEXTURE_2D, 0, m_vramTransferRect.x, m_vramTransferRect.y,
                                    m_vramTransferRect.width, m_vramTransferRect.height, GL_RGBA,
                                    GL_UNSIGNED_SHORT_1_5_5_5_REV, m_vramWriteBuffer.data());
                    m_sampleTexture.bind();
                    m_fbo.bind(OpenGL::DrawAndReadFramebuffer);
                    m_syncVRAM = true;
                    m_vramWriteBuffer.clear();

                    // Since the texture transfer has ended, this word actually marks the start of a new GP0 command
                    startGP0Command(word);
                    continue;
                }
                m_remainingWords--;
                m_vramWriteBuffer.push_back(word);
                continue;
            }

            m_remainingWords--;
            m_cmdFIFO[m_FIFOIndex++] = word;
            if (m_remainingWords == 0) {
                m_haveCommand = false;
                const auto func = m_cmdFuncs[m_cmd];
                (*this.*func)();
            }
        }
    }
}

// GP1 command writes
void PCSX::OpenGL_GPU::writeStatus(uint32_t value) {
    renderBatch();

    const uint32_t cmd = value >> 24;
    switch (cmd) {
        // Reset GPU. TODO: This should perform some more operations
        case 0:
            m_display.reset();
            setDisplayEnable(false);
            acknowledgeIRQ1();
            break;

        case 2:
            acknowledgeIRQ1();
            break;

        // Enable/Disable display
        case 3: {
            const bool enabled = (value & 1) == 0;
            setDisplayEnable(enabled);
            break;
        }

        // Set display area start
        case 5:
            m_display.setDisplayStart(value);
            break;

        // Set display area width
        case 6:
            m_display.setHorizontalRange(value);
            break;

        // Set display area height
        case 7:
            m_display.setVerticalRange(value);
            break;

        case 8:
            m_display.setMode(value);
            break;

        default:
            // PCSX::g_system->printf("Unknown GP1 command: %02X\n", cmd);
            break;
    }
}

int32_t PCSX::OpenGL_GPU::dmaChain(uint32_t* baseAddr, uint32_t addr) {
    int counter = 0;
    do {
        // if (iGPUHeight == 512) addr &= 0x1FFFFC;
        if (counter++ > 2000000) break;
        // if (::CheckForEndlessLoop(addr)) break;

        const uint32_t header = baseAddr[addr >> 2];  // Header of linked list node
        const uint32_t size = header >> 24;           // Number of words to transfer for this node

        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::Debug>()) {
            g_emulator->m_debug->checkDMAread(2, addr, (size + 1) * 4);
        }

        if (size > 0) writeDataMem(&baseAddr[(addr + 4) >> 2], size);

        addr = header & 0xffffff;
    } while (!(addr & 0x800000));  // contrary to some documentation, the end-of-linked-list marker is not actually
                                   // 0xFF'FFFF any pointer with bit 23 set will do.
    return 0;
}

bool PCSX::OpenGL_GPU::configure() {
    bool changed = false;

    if (m_shaderEditor.draw(m_gui, "Hardware renderer shader editor")) {
        const auto program = m_shaderEditor.compile(m_gui);
        if (program.has_value()) {
            m_program.m_handle = program.value();
            const auto lastProgram = OpenGL::getProgram();

            m_program.use();
            m_drawingOffsetLoc = OpenGL::uniformLocation(m_program, "u_vertexOffsets");
            m_texWindowLoc = OpenGL::uniformLocation(m_program, "u_texWindow");
            m_blendFactorsLoc = OpenGL::uniformLocation(m_program, "u_blendFactors");

            const auto vramSamplerLoc = OpenGL::uniformLocation(m_program, "u_vramTex");
            glUniform1i(vramSamplerLoc, 0);  // Make the fragment shader read from currently bound texture

            setDrawOffset(m_lastDrawOffsetSetting);
            setTexWindowUnchecked(m_lastTexwindowSetting);
            glUseProgram(lastProgram);
        }
    }

    if (ImGui::Begin(_("OpenGL GPU configuration"), &m_showCfg)) {
        static const char* polygonModeNames[] = {"Fill polygons", "Wireframe", "Vertices only"};
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
        const auto width = m_display.m_size.x();
        const auto height = m_display.m_size.y();
        const auto startX = m_display.m_start.x();
        const auto startY = m_display.m_start.y();

        ImGui::Text(_("Display horizontal range: %d-%d"), startX, startX + width);
        ImGui::Text(_("Display vertical range: %d-%d"), startY, startY + height);
        ImGui::Text(_("Drawing area offset: (%d, %d)"), m_drawingOffset.x(), m_drawingOffset.y());
        ImGui::Text(_("Resolution: %dx%d"), width, height);

        ImGui::ColorEdit3(_("Clear colour"), &m_clearColour[0]);
        if (ImGui::Button(_("Clear VRAM"))) {
            clearVRAM(m_clearColour.r(), m_clearColour.g(), m_clearColour.b());
        }

        ImGui::End();
    }
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
    if (!m_multisampled)
        return m_vramTexture.handle();
    else
        return m_vramTextureNoMSAA.handle();
}

// Called at the end of a frame
void PCSX::OpenGL_GPU::vblank() {
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
        OpenGL::disableBlend();
    }

    // We can't draw the MSAA texture directly. So if we're using MSAA, we copy the texture to a non-MSAA texture.
    if (m_multisampled) {
        m_fbo.bind(OpenGL::ReadFramebuffer);
        m_fboNoMSAA.bind(OpenGL::DrawFramebuffer);
        glBlitFramebuffer(0, 0, 1024, 512, 0, 0, 1024, 512, GL_COLOR_BUFFER_BIT, GL_LINEAR);
    }

    m_gui->setViewport();
    m_gui->flip();  // Set up offscreen framebuffer before rendering

    float startX = m_display.m_startNormalized.x();
    float startY = m_display.m_startNormalized.y();
    float width = m_display.m_sizeNormalized.x();
    float height = m_display.m_sizeNormalized.y();

    m_gui->m_offscreenShaderEditor.render(m_gui, m_displayTexture, {startX, startY}, {width, height},
                                          m_gui->getRenderSize());
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
        OpenGL::draw(OpenGL::Triangles, m_vertexCount);
        m_vertexCount = 0;
    }
}

void PCSX::OpenGL_GPU::setDisplayEnable(bool setting) {
    m_display.m_enabled = setting;
    if (!setting) {
        m_displayTexture = m_blankTexture.handle();
    } else {
        m_displayTexture = m_multisampled ? m_vramTextureNoMSAA.handle() : m_vramTexture.handle();
    }
}

void PCSX::OpenGL_GPU::save(SaveStates::GPU& gpu) { g_system->printf("Unimplemented OpenGL GPU function: save\n"); }

void PCSX::OpenGL_GPU::load(const SaveStates::GPU& gpu) { g_system->printf("TODO: load\n"); }

PCSX::GPU::ScreenShot PCSX::OpenGL_GPU::takeScreenShot() {
    ScreenShot ss;
    ss.width = 0;
    ss.height = 0;
    ss.data.acquire(nullptr, 0);
    return ss;
}

void PCSX::OpenGL_GPU::startDump() { g_system->printf("Unimplemented OpenGL GPU function: startDump\n"); }

void PCSX::OpenGL_GPU::stopDump() { g_system->printf("Unimplemented OpenGL GPU function: stopDump\n"); }
