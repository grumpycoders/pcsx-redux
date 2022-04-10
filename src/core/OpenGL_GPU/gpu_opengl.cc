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

void PCSX::OpenGL_GPU::clearVRAM() {
    const auto oldFBO = OpenGL::getDrawFramebuffer();
    m_fbo.bind(OpenGL::DrawFramebuffer);
    OpenGL::setClearColor(0.f, 0.f, 0.f, 1.f);
    OpenGL::clearColor();
    glBindFramebuffer(GL_DRAW_FRAMEBUFFER, oldFBO);
}

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
    m_vao.setAttribute(0, 2, GL_FLOAT, false, sizeof(Vertex), offsetof(Vertex, positions));
    m_vao.enableAttribute(0);
    // Colour (r, g, b) attribute
    m_vao.setAttribute(1, 3, GL_FLOAT, false, sizeof(Vertex), offsetof(Vertex, colors));
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
        layout (location = 0) in vec2 aPos;
        layout (location = 1) in vec3 Color;
        out vec4 vertexColor;

        void main() {
           // Normalize coords to [0, 2]
           // The - 0.5 helps fix some holes in rendering, in places like the PS logo
           // TODO: This might not work when upscaling?
           float xx = (aPos.x - 0.5) / 512.0;
           float yy = (aPos.y - 0.5) / 256;

           // Normalize to [-1, 1]
           xx -= 1.0;
           yy -= 1.0;
           
           gl_Position = vec4(xx, yy, 1.0, 1.0);
           vertexColor = vec4(Color / 255.0, 1.0);
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
    return m_gpustat;
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
                case 0xE5:                  // Set draw offset
                    m_haveCommand = false;  // No params, move straight to the next command
                    PCSX::g_system->printf("Unimplemented set draw offset command: %08X\n", word);
                    break;
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
                    const uint32_t colour = m_cmdFIFO[0] & 0xffffff;
                    const float r = colour & 0xff;
                    const float g = (colour >> 8) & 0xff;
                    const float b = (colour >> 16) & 0xff;

                    for (auto i = 0; i < 3; i++) {
                        const uint32_t v = m_cmdFIFO[i + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, r, g, b)));
                    }

                    for (auto i = 1; i < 4; i++) {
                        const uint32_t v = m_cmdFIFO[i + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        m_vertices.push_back(std::move(Vertex(x, y, r, g, b)));
                    }
                }

                else if (m_cmd == 0x20) {
                    const uint32_t colour = m_cmdFIFO[0] & 0xffffff;
                    for (int i = 0; i < 3; i++) {
                        const uint32_t v = m_cmdFIFO[i + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        const float r = colour & 0xff;
                        const float g = (colour >> 8) & 0xff;
                        const float b = (colour >> 16) & 0xff;
                        m_vertices.push_back(std::move(Vertex(x, y, r, g, b)));
                    }
                }

                else if (m_cmd == 0x30) {
                    for (int i = 0; i < 3; i++) {
                        const uint32_t colour = m_cmdFIFO[i * 2] & 0xffffff;
                        const uint32_t v = m_cmdFIFO[i * 2 + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        const float r = colour & 0xff;
                        const float g = (colour >> 8) & 0xff;
                        const float b = (colour >> 16) & 0xff;
                        m_vertices.push_back(std::move(Vertex(x, y, r, g, b)));
                    }
                }

                else if (m_cmd == 0x38) {
                    for (int i = 0; i < 3; i++) {
                        const uint32_t colour = m_cmdFIFO[i * 2] & 0xffffff;
                        const uint32_t v = m_cmdFIFO[i * 2 + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        const float r = colour & 0xff;
                        const float g = (colour >> 8) & 0xff;
                        const float b = (colour >> 16) & 0xff;
                        m_vertices.push_back(std::move(Vertex(x, y, r, g, b)));
                    }

                    for (int i = 1; i < 4; i++) {
                        const uint32_t colour = m_cmdFIFO[i * 2] & 0xffffff;
                        const uint32_t v = m_cmdFIFO[i * 2 + 1];
                        const uint32_t x = v & 0xffff;
                        const uint32_t y = v >> 16;
                        const float r = colour & 0xff;
                        const float g = (colour >> 8) & 0xff;
                        const float b = (colour >> 16) & 0xff;
                        m_vertices.push_back(std::move(Vertex(x, y, r, g, b)));
                    }
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

void PCSX::OpenGL_GPU::writeStatus(uint32_t value) { g_system->printf("TODO: writeStatus\n"); }

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
    // g_system->printf("TODO: configure\n");
    return false;
}

// Called at the start of a frame
void PCSX::OpenGL_GPU::startFrame() {
    m_vbo.bind();
    m_vao.bind();
    m_fbo.bind(OpenGL::DrawFramebuffer);
    OpenGL::setViewport(m_vramTexture.width(), m_vramTexture.height());
    m_untexturedTriangleProgram.use();
}

// Called at the end of a frame
void PCSX::OpenGL_GPU::updateLace() {
    if (!m_vertices.empty()) {
        renderBatch();
    }

    m_gui->setViewport();
    m_gui->flip();  // Set up offscreen framebuffer before rendering
    m_gui->m_offscreenShaderEditor.render(m_gui, m_vramTexture.handle(), {0, 0}, {1, 1}, m_gui->getRenderSize());
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
