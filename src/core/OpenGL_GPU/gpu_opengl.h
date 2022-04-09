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

#pragma once

#include <array>

#include "core/gpu.h"
#include "support/opengl.h"

namespace PCSX {

enum class TransferMode { CommandTransfer, VRAMTransfer };

class OpenGL_GPU final : public GPU {
    using GP0Func = void (OpenGL_GPU::*)();  // A function pointer to a drawing function
    struct Vertex {
        float positions[2];
        float colors[3];

        Vertex(float x, float y, float r, float g, float b) {
            positions[0] = x;
            positions[1] = y;
            colors[0] = r;
            colors[1] = g;
            colors[2] = b;
        }
    };

    virtual int init() final;
    virtual int shutdown() final;
    virtual int open(GUI *) final;
    virtual int close() final;
    virtual uint32_t readData() final;
    virtual void startDump() final;
    virtual void stopDump() final;
    virtual void readDataMem(uint32_t *dest, int size) final;
    virtual uint32_t readStatus() final;
    virtual void writeData(uint32_t value) final;
    virtual void writeDataMem(uint32_t *source, int size) final;
    virtual void writeStatus(uint32_t value) final;
    virtual int32_t dmaChain(uint32_t *baseAddrL, uint32_t addr) final;
    virtual void startFrame() final;
    virtual void updateLace() final;
    virtual bool configure() final;

    uint32_t m_gpustat = 0x14802000;
    uint8_t *m_vram = nullptr;
    GUI *m_gui = nullptr;
    int m_useDither = 0;
    int m_height = 512;

    static constexpr int vramWidth = 1024;
    static constexpr int vramHeight = 512;

    TransferMode m_readingMode;
    TransferMode m_writingMode;
    
    OpenGL::Program m_untexturedTriangleProgram;
    OpenGL::VertexArray m_vao;
    OpenGL::VertexBuffer m_vbo;
    OpenGL::Framebuffer m_fbo;
    OpenGL::Texture m_vramTexture;

    std::vector<Vertex> m_vertices;
    std::array<uint32_t, 16> m_cmdFIFO;
    std::array<GP0Func, 256> m_gp0Funcs;
    int m_FIFOIndex;
    int m_cmd;

    int m_remainingWords = 0;
    bool m_haveCommand = false;
    bool m_textureLoad = false;
    virtual void save(SaveStates::GPU &gpu) final;

    virtual void load(const SaveStates::GPU &gpu) final;
    virtual void setDither(int setting) final { m_useDither = setting; }
    virtual uint8_t *getVRAM() final { return m_vram; }
    virtual void clearVRAM() final {
        std::memset(m_vram, 0x00, m_height * 2 * 1024 + (1024 * 1024));
    }  // Clear VRAM to 0s
    virtual GLuint getVRAMTexture() final { return m_vramTexture.handle(); }

    void initGP0Funcs();
    void renderBatch();
};
}  // namespace PCSX
