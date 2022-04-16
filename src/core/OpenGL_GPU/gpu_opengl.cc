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
    m_FIFOIndex = 0;
    m_vertices.clear();
    clearVRAM();
}

void PCSX::OpenGL_GPU::clearVRAM(float r, float g, float b, float a) {
    const auto oldFBO = OpenGL::getDrawFramebuffer();
    m_fbo.bind(OpenGL::DrawFramebuffer);
    OpenGL::setClearColor(r, g, b, a);
    OpenGL::clearColor();
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, oldFBO);
}

void PCSX::OpenGL_GPU::clearVRAM() { clearVRAM(0.f, 0.f, 0.f, 1.f); }

// Do not forget to call this with an active OpenGL context.
int PCSX::OpenGL_GPU::init() {
    g_system->printf("TODO: init\n");
    reset();

    // Reserve some size for vertices to avoid dynamic allocations later.
    m_vertices.reserve(0x10000);

    m_vbo.create();
    m_vbo.bind();
    m_vao.create();
    m_vao.bind();

    // Position (x and y coord) attribute
    m_vao.setAttribute<GLuint>(0, 2, sizeof(Vertex), offsetof(Vertex, positions));
    m_vao.enableAttribute(0);
    // Colour attribute
    m_vao.setAttribute<GLuint>(1, 1, sizeof(Vertex), offsetof(Vertex, colour));
    m_vao.enableAttribute(1);

    // Make VRAM texture and attach it to draw frambuffer
    m_vramTexture.create(vramWidth, vramHeight, GL_RGBA8);
    m_fbo.createWithDrawTexture(m_vramTexture);
    m_fbo.bind(OpenGL::DrawFramebuffer);
    // Clear VRAM texture
    OpenGL::setClearColor(0.0, 0, 0, 1.0);
    OpenGL::clearColor();
    m_gui->signalVRAMTextureCreated(m_vramTexture.handle());

    if (glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        throw std::runtime_error("Non-complete framebuffer");
    }

    OpenGL::bindScreenFramebuffer();

    static const char* vertSource = R"(
        #version 330 core

        // inPos: The vertex position.
        // inColor: The colour in BGR888. Top 8 bits are garbage and are trimmed by the vertex shader to conserve CPU time 

        layout (location = 0) in uvec2 inPos;
        layout (location = 1) in uint inColor;
        out vec4 vertexColor;

        // We always apply a -0.5 offset in addition to the drawing offsets, to cover up OpenGL inaccuracies 
        uniform vec2 u_vertexOffsets = vec2(-0.5, -0.5);

        void main() {
           // Normalize coords to [0, 2]
           float x = float(inPos.x);
           float y = float(inPos.y);
           float xx = (x + u_vertexOffsets.x) / 512.0;
           float yy = (y + u_vertexOffsets.y) / 256;

           // Normalize to [-1, 1]
           xx -= 1.0;
           yy -= 1.0;

           float red = float(inColor & 0xff);
           float green = float((inColor >> 8) & 0xff);
           float blue = float((inColor >> 16) & 0xff);
           vec3 color = vec3(red, green, blue);
           
           gl_Position = vec4(xx, yy, 1.0, 1.0);
           vertexColor = vec4(color / 255.0, 1.0);
        }
    )";

    static const char* fragSource = R"(
        #version 330 core
        in vec4 vertexColor;
        out vec4 FragColor;

        void main() {
           FragColor = vertexColor;
        }
    )";

    OpenGL::Shader frag(fragSource, OpenGL::Fragment);
    OpenGL::Shader vert(vertSource, OpenGL::Vertex);
    m_untexturedTriangleProgram.create({frag, vert});
    m_untexturedTriangleProgram.use();

    m_drawingOffsetLoc = OpenGL::uniformLocation(m_untexturedTriangleProgram, "u_vertexOffsets");
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
    g_system->printf("TODO: readData\n");
    return 0;
}

void PCSX::OpenGL_GPU::readDataMem(uint32_t* destination, int size) { g_system->printf("TODO: readDataMem\n"); }

void PCSX::OpenGL_GPU::writeData(uint32_t value) { writeDataMem(&value, 1); }

void PCSX::OpenGL_GPU::writeDataMem(uint32_t* source, int size) {
    ZoneScoped;  // Let Tracy do its thing

    while (size) {
        const uint32_t word = *source++;  // Fetch word, inc pointer. TODO: Better bounds checking.
        size--;
    start:
        if (!m_haveCommand) {
            const uint32_t cmd = word >> 24;
            m_cmd = cmd;
            m_haveCommand = true;
            m_cmdFIFO[0] = word;
            m_FIFOIndex = 1;

            switch (cmd) {
                case 0x00:                  // nop
                    m_haveCommand = false;  // No params, move straight to the next command
                    break;
                case 0x01:                  // Clear texture cache
                    m_haveCommand = false;  // No params, move straight to the next command
                    break;
                case 0x02:  // Fill rectangle in VRAM with solid colour
                    m_remainingWords = 2;
                    break;
                case 0x20:  // Monochrome triangle
                case 0x22:  // Monochrome triangle, semi-transparent (unimplemented)
                    m_remainingWords = 3;
                    break;
                case 0x28:  // Monochrome quad
                    m_remainingWords = 4;
                    break;
                case 0x2C:  // Texured quad with blending
                case 0x2D:  // Textured quad, opaque, no blending
                case 0x2F:  // Textured quad, semi transparent, no blending
                    m_remainingWords = 8;
                    break;
                case 0x30:  // Shaded triangle
                    m_remainingWords = 5;
                    break;
                case 0x38:  // Shaded quad
                    m_remainingWords = 7;
                    break;
                case 0x60: // Monochrome Rectangle
                    m_remainingWords = 2;
                    break;
                case 0x65:  // Textured rect, opaque, no blending
                    m_remainingWords = 3;
                    break;
                case 0xA0:  // Copy rectangle (CPU->VRAM)
                    m_remainingWords = 2;
                    break;
                case 0xC0:  // Copy rectangle (CPU->VRAM)
                    m_remainingWords = 2;
                    PCSX::g_system->printf("Unimplemented read rectangle command: %08X\n", word);
                    break;

                case 0xE1:                  // Set draw mode
                    m_haveCommand = false;  // No params, move straight to the next command
                    PCSX::g_system->printf("Unimplemented set draw mode command: %08X\n", word);
                    break;
                case 0xE2:                  // Set texture window
                    m_haveCommand = false;  // No params, move straight to the next command
                    PCSX::g_system->printf("Unimplemented set texture window command: %08X\n", word);
                    break;
                case 0xE3:                  // Set draw area top left
                    m_haveCommand = false;  // No params, move straight to the next command
                    PCSX::g_system->printf("Unimplemented set draw area top left command: %08X\n", word);
                    break;
                case 0xE4:                  // Set draw area bottom right
                    m_haveCommand = false;  // No params, move straight to the next command
                    PCSX::g_system->printf("Unimplemented set draw area bottom right command: %08X\n", word);
                    break;
                case 0xE5: {
                    m_haveCommand = false; // No params, move straight to the next command
                    // Offset is a signed number in [-1024, 1023]
                    const auto offsetX = (int32_t)word << 21 >> 21;
                    const auto offsetY = (int32_t)word << 10 >> 21;
                    
                    m_drawingOffset.x() = static_cast<float>(offsetX);
                    m_drawingOffset.y() = static_cast<float>(offsetY);

                    // The - 0.5 helps fix some holes in rendering, in places like the PS logo
                    // TODO: This might not work when upscaling?
                    float adjustedOffsets[2] = {m_drawingOffset.x() - 0.5, m_drawingOffset.y() - 0.5};
                    glUniform2fv(m_drawingOffsetLoc, 1, adjustedOffsets);
                    break;
                }
                case 0xE6:                  // Set draw mask
                    m_haveCommand = false;  // No params, move straight to the next command
                    PCSX::g_system->printf("Unimplemented set draw mask command: %08X\n", word);
                    break;
                default:
                    m_haveCommand = false;
                    PCSX::g_system->printf("Unknown GP0 command: %02X\n", cmd);
                    break;
            }
        } else {
            if (m_writingMode == TransferMode::VRAMTransfer) {
                if (m_remainingWords == 0) {
                    m_writingMode = TransferMode::CommandTransfer;
                    m_haveCommand = false;
                    goto start;
                }
                m_remainingWords--;
                continue;
            }

            m_remainingWords--;
            m_cmdFIFO[m_FIFOIndex++] = word;
            if (m_remainingWords == 0) {
                m_haveCommand = false;
                if (m_cmd == 0x28) {
                    const uint32_t colour = m_cmdFIFO[0];

                    for (auto i = 0; i < 3; i++) {
                        const uint32_t v = m_cmdFIFO[i + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, colour)));
                    }

                    for (auto i = 1; i < 4; i++) {
                        const uint32_t v = m_cmdFIFO[i + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, colour)));
                    }
                }

                else if (m_cmd == 0x20) {
                    const uint32_t colour = m_cmdFIFO[0];
                    for (int i = 0; i < 3; i++) {
                        const uint32_t v = m_cmdFIFO[i + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, colour)));
                    }
                }

                else if (m_cmd == 0x30) {
                    for (int i = 0; i < 3; i++) {
                        const uint32_t colour = m_cmdFIFO[i * 2];
                        const uint32_t v = m_cmdFIFO[i * 2 + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, colour)));
                    }
                }

                else if (m_cmd == 0x38) {
                    for (int i = 0; i < 3; i++) {
                        const uint32_t colour = m_cmdFIFO[i * 2];
                        const uint32_t v = m_cmdFIFO[i * 2 + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, colour)));
                    }

                    for (int i = 1; i < 4; i++) {
                        const uint32_t colour = m_cmdFIFO[i * 2];
                        const uint32_t v = m_cmdFIFO[i * 2 + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, colour)));
                    }
                }

                else if (m_cmd == 0x60) {
                    const uint32_t colour = m_cmdFIFO[0];
                    const uint32_t v = m_cmdFIFO[1];
                    const uint32_t size = m_cmdFIFO[2];

                    const uint32_t x = v & 0xffff;
                    const uint32_t y = v >> 16;
                    const uint32_t width = size & 0xffff;
                    const uint32_t height = size >> 16;

                    m_vertices.push_back(std::move(Vertex(x, y, colour)));
                    m_vertices.push_back(std::move(Vertex(x + width, y, colour)));
                    m_vertices.push_back(std::move(Vertex(x + width, y + height, colour)));

                    m_vertices.push_back(std::move(Vertex(x + width, y + height, colour)));
                    m_vertices.push_back(std::move(Vertex(x, y + height, colour)));
                    m_vertices.push_back(std::move(Vertex(x, y, colour)));
                }

                else if (m_cmd == 0xA0) {
                    m_writingMode = TransferMode::VRAMTransfer;
                    m_haveCommand = true;
                    const uint32_t res = m_cmdFIFO[2];
                    const uint32_t width = res & 0xffff;
                    const uint32_t height = res >> 16;
                    if (width == 0 || height == 0)
                        PCSX::g_system->printf("Weird %dx%d texture transfer\n", width, height);

                    // The size of the texture in 16-bit pixels. If the number is odd, force align it up
                    const uint32_t size = ((width * height) + 1) & ~1;
                    m_remainingWords = size / 2;
                }

                else if (m_cmd == 0x02) {
                    const auto colour = m_cmdFIFO[0] & 0xffffff;
                    const float r = float(colour & 0xff) / 255.f;
                    const float g = float((colour >> 8) & 0xff) / 255.f;
                    const float b = float((colour >> 16) & 0xff) / 255.f;

                    OpenGL::setClearColor(r, g, b, 1.f);
                    const uint32_t x0 = m_cmdFIFO[1] & 0xffff;
                    const uint32_t y0 = m_cmdFIFO[1] >> 16;
                    const uint32_t width = m_cmdFIFO[2] & 0xffff;
                    const uint32_t height = m_cmdFIFO[2] >> 16;

                    // Fix this when we implement the drawing area lmao
                    OpenGL::enableScissor();
                    OpenGL::setScissor(x0, y0, width, height);
                    OpenGL::clearColor();
                    OpenGL::disableScissor();
                }
            }
        }
    }
}

// GP1 command writes
void PCSX::OpenGL_GPU::writeStatus(uint32_t value) {
    g_system->printf("TODO: writeStatus\n");

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

            // m_displayArea.width = (((x2 - x1) / cyclesPerPix) + 2) & ~3;
            m_displayArea.width = 320;
            break;
        }

        case 7: {
            const auto y1 = value & 0x3ff;
            const auto y2 = (value >> 10) & 0x3ff;

            m_displayArea.height = y2 - y1;
            break;
        }
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
        ImGui::Text(_("Drawing area offset: (%d, %d)"), static_cast<int>(m_drawingOffset.x()),
                    static_cast<int>(m_drawingOffset.y()));

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
    m_fbo.bind(OpenGL::DrawFramebuffer);
    OpenGL::setViewport(m_vramTexture.width(), m_vramTexture.height());
    OpenGL::setFillMode(m_polygonMode);
    m_untexturedTriangleProgram.use();
}

// Called at the end of a frame
void PCSX::OpenGL_GPU::vblank() {
    if (!m_vertices.empty()) {
        renderBatch();
    }

    // Set the fill mode to fill before passing the OpenGL context to the GUI
    if (m_polygonMode != OpenGL::FillPoly) {
        OpenGL::setFillMode(OpenGL::FillPoly);
    }

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
    const auto vertexCount = m_vertices.size();
    m_vbo.bufferVerts(&m_vertices[0], vertexCount);
    OpenGL::draw(OpenGL::Triangles, vertexCount);
    m_vertices.clear();
}

void PCSX::OpenGL_GPU::save(SaveStates::GPU& gpu) { g_system->printf("TODO: save\n"); }

void PCSX::OpenGL_GPU::load(const SaveStates::GPU& gpu) { g_system->printf("TODO: load\n"); }

void PCSX::OpenGL_GPU::startDump() { g_system->printf("TODO: startDump\n"); }
    
void PCSX::OpenGL_GPU::stopDump() { g_system->printf("TODO: stopDump\n"); }
