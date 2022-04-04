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

#include <stdexcept>

#include "core/system.h"
#include "fmt/format.h"
#include "gui/gui.h"
#include "tracy/Tracy.hpp"

std::unique_ptr<PCSX::GPU> PCSX::GPU::getOpenGL() { return std::unique_ptr<PCSX::GPU>(new PCSX::OpenGL_GPU()); }

int PCSX::OpenGL_GPU::init() {
    g_system->printf("TODO: init\n");
    // Allocate some extra space for safety
    m_vram = new uint8_t[m_height * 2 * 1024 + 1024 * 1024]();
    m_gpustat = 0x14802000;

    m_readingMode = TransferMode::CommandTransfer;
    m_writingMode = TransferMode::CommandTransfer;

    m_vao.create();
    m_vbo.create();
    m_vao.bind();

    m_vramTexture.create(vramWidth, vramHeight, GL_RGBA8);
    m_fbo.createWithDrawTexture(m_vramTexture);
    if (glCheckFramebufferStatus(GL_DRAW_FRAMEBUFFER) != GL_FRAMEBUFFER_COMPLETE) {
        throw std::runtime_error("Non-complete framebuffer");
    }

    OpenGL::bindScreenFramebuffer();

    static const char* vertSource =
        "#version 330 core\n"
        "layout (location = 0) in vec2 aPos;\n"
        "void main() {\n"
        "   gl_Position = vec4(aPos.x, aPos.y, 1.0, 1.0);\n"
        "}";

    static const char* fragSource =
        "#version 330 core\n"
        "out vec4 FragColor;\n"
        "void main() {\n"
        "    FragColor = vec4(1.0f, 0.5f, 0.2f, 1.0f);\n"
        "}";

    OpenGL::Shader frag(fragSource, OpenGL::Fragment);
    OpenGL::Shader vert(vertSource, OpenGL::Vertex);
    m_untexturedTriangleProgram.create({frag, vert});

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

    if (m_writingMode == TransferMode::VRAMTransfer) {
        g_system->printf("Transferring texture data\n");
    } else {
        g_system->printf("Transferring command data\n");
    }
}

void PCSX::OpenGL_GPU::writeStatus(uint32_t value) { g_system->printf("TODO: writeStatus\n"); }

int32_t PCSX::OpenGL_GPU::dmaChain(uint32_t* baseAddr, uint32_t addr) {
    g_system->printf("TODO: writeDMAChain\n");
    return 0;
}

bool PCSX::OpenGL_GPU::configure() {
    // g_system->printf("TODO: configure\n");
    return false;
}

// Called at the start of a frame
void PCSX::OpenGL_GPU::startFrame() {
    m_vao.bind();
    m_fbo.bind(OpenGL::DrawFramebuffer);
    OpenGL::setViewport(m_vramTexture.width(), m_vramTexture.height());

    m_untexturedTriangleProgram.use();
}

struct VertexData {
    float x, y;
};

// Called at the end of a frame
void PCSX::OpenGL_GPU::updateLace() {
    m_fbo.bind(OpenGL::DrawFramebuffer);
    OpenGL::setClearColor(1.f, 0.f, 1.f, 1.f);
    OpenGL::clearColor();
    m_gui->setViewport();
    m_gui->flip(); // Set up offscreen framebuffer before rendering

    m_gui->m_offscreenShaderEditor.render(m_gui, m_vramTexture.handle(), {1024.0f, 512.0f}, {0, 0}, {1, 1},
                                          m_gui->getRenderSize());
}

void PCSX::OpenGL_GPU::save(SaveStates::GPU& gpu) { g_system->printf("TODO: save\n"); }

void PCSX::OpenGL_GPU::load(const SaveStates::GPU& gpu) { g_system->printf("TODO: load\n"); }

void PCSX::OpenGL_GPU::startDump() { g_system->printf("TODO: startDump\n"); }

void PCSX::OpenGL_GPU::stopDump() { g_system->printf("TODO: stopDump\n"); }
