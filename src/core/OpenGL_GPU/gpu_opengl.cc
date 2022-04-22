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
    m_readingMode = TransferMode::CommandTransfer;
    m_writingMode = TransferMode::CommandTransfer;
    m_remainingWords = 0;
    m_vramReadBufferSize = 0;
    m_FIFOIndex = 0;
    m_vertexCount = 0;
    m_vramReadBuffer.clear();
    m_vramWriteBuffer.clear();
    m_displayArea.setEmpty();

    m_drawAreaLeft = m_drawAreaTop = 0;
    m_drawAreaBottom = vramHeight;
    m_drawAreaRight = vramWidth;
    updateDrawArea();

    m_drawingOffset = OpenGL::ivec2({0, 0});

    float adjustedOffsets[2] = {+0.5f, -0.5f};
    glUniform2fv(m_drawingOffsetLoc, 1, adjustedOffsets);

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
    m_vertices.reserve(vertexBufferSize);
    m_vramReadBuffer.reserve(vramWidth * vramHeight);
    m_vramWriteBuffer.reserve(vramWidth * vramHeight);

    m_vbo.create();
    m_vbo.bind();
    m_vao.create();
    m_vao.bind();

    // Position (x and y coord) attribute. Signed 11-bit numbers
    m_vao.setAttribute<GLint>(0, 2, sizeof(Vertex), offsetof(Vertex, positions));
    m_vao.enableAttribute(0);
    // Colour attribute
    m_vao.setAttribute<GLuint>(1, 1, sizeof(Vertex), offsetof(Vertex, colour));
    m_vao.enableAttribute(1);

    // Make VRAM texture and attach it to draw frambuffer
    m_vramTexture.create(vramWidth, vramHeight, GL_RGBA8);
    m_fbo.createWithTexture(m_vramTexture);
    m_gui->signalVRAMTextureCreated(m_vramTexture.handle());

    m_sampleTexture.create(vramWidth, vramHeight, GL_RGBA8);

    if (glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        throw std::runtime_error("Non-complete framebuffer");
    }

    OpenGL::bindScreenFramebuffer();

    static const char* vertSource = R"(
        #version 330 core

        // inPos: The vertex position.
        // inColor: The colour in BGR888. Top 8 bits are garbage and are trimmed by the vertex shader to conserve CPU time 

        layout (location = 0) in ivec2 inPos;
        layout (location = 1) in uint inColor;
        out vec4 vertexColor;

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
        }
    )";

    static const char* fragSource = R"(
        #version 330 core
        in vec4 vertexColor;
        out vec4 FragColor;

        uniform sampler2D u_vramTex;

        void main() {
           FragColor = vertexColor;
        }
    )";

    OpenGL::Shader frag(fragSource, OpenGL::Fragment);
    OpenGL::Shader vert(vertSource, OpenGL::Vertex);
    m_untexturedTriangleProgram.create({frag, vert});
    m_untexturedTriangleProgram.use();
    m_drawingOffsetLoc = OpenGL::uniformLocation(m_untexturedTriangleProgram, "u_vertexOffsets");

    const auto vramSamplerLoc = OpenGL::uniformLocation(m_untexturedTriangleProgram, "u_vramTex");
    glUniform1i(vramSamplerLoc, 0); // Make the fragment shader read from currently binded texture

    reset();
    initCommands();
    return 0;
}

int PCSX::OpenGL_GPU::shutdown() {
    g_system->printf("TODO: shutdown\n");
    return 0;
}

int PCSX::OpenGL_GPU::open(GUI* gui) {
    m_gui = gui;
    return 0;
}

int PCSX::OpenGL_GPU::close() {
    g_system->printf("TODO: close\n");
    return 0;
}

uint32_t PCSX::OpenGL_GPU::readStatus() {
    g_system->printf("GPUSTAT read\n");
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
            g_system->printf("Don't know how to handle this GPUREAD read :(\n");
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
    start:
        if (!m_haveCommand) {
            startGP0Command(word);
        } else {
            if (m_writingMode == TransferMode::VRAMTransfer) {
                if (m_remainingWords == 0) { // Texture transfer finished
                    renderBatch();
                    m_writingMode = TransferMode::CommandTransfer;
                    m_haveCommand = false;

                    OpenGL::bindScreenFramebuffer();
                    m_vramTexture.bind();
                    glTexSubImage2D(GL_TEXTURE_2D, 0, m_vramTransferRect.x, m_vramTransferRect.y,
                                    m_vramTransferRect.width, m_vramTransferRect.height, GL_RGBA,
                                    GL_UNSIGNED_SHORT_1_5_5_5_REV, &m_vramWriteBuffer[0]);
                    m_sampleTexture.bind();
                    m_fbo.bind(OpenGL::DrawAndReadFramebuffer);
                    glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 0, 0, vramWidth, vramHeight);
                    m_vramWriteBuffer.clear();
                    goto start;
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
        // Set display area start
        case 5:
            m_displayArea.x = value & 0x3ff;
            m_displayArea.y = (value >> 10) & 0x1ff;
            break;
        // Set display area width
        case 6: {
            const auto x1 = value & 0xfff;
            const auto x2 = (value >> 12) & 0xfff;
            constexpr uint32_t cyclesPerPix = 2560;

            //m_displayArea.width = (((x2 - x1) / cyclesPerPix) + 2) & ~3;
            m_displayArea.width = 320;
            break;
        }

        case 7: {
            const auto y1 = value & 0x3ff;
            const auto y2 = (value >> 10) & 0x3ff;

            m_displayArea.height = y2 - y1;
            break;
        }

        default:
            PCSX::g_system->printf("Unknown GP1 command: %02X\n", cmd);
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

        ImGui::End();
    }

    return false;
}

void PCSX::OpenGL_GPU::debug() {
    if (ImGui::Begin(_("OpenGL GPU Debugger"), &m_showDebug)) {
        ImGui::Text(_("Display horizontal range: %d-%d"), m_displayArea.x, m_displayArea.x + m_displayArea.width);
        ImGui::Text(_("Display vertical range: %d-%d"), m_displayArea.y, m_displayArea.y + m_displayArea.height);
        ImGui::Text(_("Drawing area offset: (%d, %d)"), m_drawingOffset.x(), m_drawingOffset.y());

        ImGui::ColorEdit3(_("Clear colour"), &m_clearColour[0]);
        if (ImGui::Button(_("Clear VRAM"))) {
            clearVRAM(m_clearColour.r(), m_clearColour.g(), m_clearColour.b());
        }

        ImGui::End();
    }
}

// Called at the start of a frame
void PCSX::OpenGL_GPU::startFrame() {
    m_vbo.bind();
    m_vao.bind();
    m_fbo.bind(OpenGL::DrawAndReadFramebuffer);
    m_sampleTexture.bind();
    OpenGL::setViewport(m_vramTexture.width(), m_vramTexture.height());
    OpenGL::enableScissor();

    if (m_polygonMode != OpenGL::FillPoly) {
        OpenGL::setFillMode(m_polygonMode);
    }

    m_untexturedTriangleProgram.use();
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

// Called at the end of a frame
void PCSX::OpenGL_GPU::vblank() {
    renderBatch();

    // Set the fill mode to fill before passing the OpenGL context to the GUI
    if (m_polygonMode != OpenGL::FillPoly) {
        OpenGL::setFillMode(OpenGL::FillPoly);
    }

    // Also remove our scissor before passing the OpenGL context to the GUI
    OpenGL::disableScissor();
    m_gui->setViewport();
    m_gui->flip();  // Set up offscreen framebuffer before rendering

    // TODO: Handle 24-bit display here.
    float xRatio = false ? ((1.0f / 1.5f) * (1.0f / 1024.0f)) : (1.0f / 1024.0f);

    float startX = m_displayArea.x * xRatio;
    float startY = m_displayArea.y / 512.0f;
    float width = m_displayArea.width / 1024.0f;
    float height = m_displayArea.height / 512.0f;

    m_gui->m_offscreenShaderEditor.render(m_gui, m_vramTexture.handle(), {startX, startY}, {width, height},
                                          m_gui->getRenderSize());
}

void PCSX::OpenGL_GPU::renderBatch() {
    if (m_vertexCount > 0) {
        m_vbo.bufferVerts(&m_vertices[0], m_vertexCount);
        OpenGL::draw(OpenGL::Triangles, m_vertexCount);
        m_vertexCount = 0;
    }
}

void PCSX::OpenGL_GPU::save(SaveStates::GPU& gpu) { g_system->printf("TODO: save\n"); }

void PCSX::OpenGL_GPU::load(const SaveStates::GPU& gpu) { g_system->printf("TODO: load\n"); }

void PCSX::OpenGL_GPU::startDump() { g_system->printf("TODO: startDump\n"); }
    
void PCSX::OpenGL_GPU::stopDump() { g_system->printf("TODO: stopDump\n"); }
