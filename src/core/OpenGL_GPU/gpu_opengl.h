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
#include <vector>

#include "core/gpu.h"
#include "support/opengl.h"

namespace PCSX {
class OpenGL_GPU final : public GPU {
    // Interface functions
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
    virtual void vblank() final;
    virtual bool configure() final;
    virtual void debug() final;

    virtual void save(SaveStates::GPU &gpu) final;

    virtual void load(const SaveStates::GPU &gpu) final;
    virtual void setDither(int setting) final { m_useDither = setting; }
    virtual void clearVRAM() final;
    virtual void reset() final;
    virtual GLuint getVRAMTexture() final;

    // Actual emulation stuff
    using GP0Func = void (OpenGL_GPU::*)();  // A function pointer to a drawing function
    struct Vertex {
        OpenGL::ivec2 positions;
        uint32_t colour;
        uint16_t texpage;
        uint16_t clut;
        OpenGL::Vector<uint16_t, 2> uv;

        // We use bit 15 of the texpage attribute (normally unused) to indicate an untextured prim.
        static constexpr uint16_t c_untexturedPrimitiveTexpage = 0x8000;

        Vertex(uint32_t x, uint32_t y, uint32_t col) {
            positions.x() = int(x) << 21 >> 21;
            positions.y() = int(y) << 21 >> 21;
            colour = col;
            texpage = c_untexturedPrimitiveTexpage;
        }

        Vertex(uint32_t position, uint32_t col) {
            const int x = position & 0xffff;
            const int y = (position >> 16) & 0xffff;
            positions.x() = x << 21 >> 21;
            positions.y() = y << 21 >> 21;
            colour = col;
            texpage = c_untexturedPrimitiveTexpage;
        }

        Vertex(uint32_t position, uint32_t col, uint16_t clut, uint16_t texpage,  uint32_t texcoords)
            : colour(col), clut(clut), texpage(texpage) {
            const int x = position & 0xffff;
            const int y = (position >> 16) & 0xffff;
            positions.x() = x << 21 >> 21;
            positions.y() = y << 21 >> 21;

            uv.u() = texcoords & 0xff;
            uv.v() = (texcoords >> 8) & 0xff;
        }

        Vertex(uint32_t x, uint32_t y, uint32_t col, uint16_t clut, uint16_t texpage, uint16_t u, uint16_t v)
            : colour(col), clut(clut), texpage(texpage) {
            positions.x() = int(x) << 21 >> 21;
            positions.y() = int(y) << 21 >> 21;

            uv.u() = u;
            uv.v() = v;
        }
    };
    enum class TransferMode { CommandTransfer, VRAMTransfer };

    uint32_t m_gpustat = 0x14802000;
    GUI *m_gui = nullptr;
    int m_useDither = 0;

    static constexpr int vramWidth = 1024;
    static constexpr int vramHeight = 512;
    static constexpr int vertexBufferSize = 0x100000;

    TransferMode m_readingMode;
    TransferMode m_writingMode;

    OpenGL::Program m_untexturedTriangleProgram;
    OpenGL::VertexArray m_vao;
    OpenGL::VertexBuffer m_vbo;
    OpenGL::Framebuffer m_fbo;
    OpenGL::Texture m_vramTexture;

    // We need non-MSAA copies of our texture & FBO when using multisampling
    OpenGL::Texture m_vramTextureNoMSAA;
    OpenGL::Framebuffer m_fboNoMSAA;
    
    // For CPU->VRAM texture transfers
    OpenGL::Texture m_sampleTexture;
    OpenGL::Rect m_vramTransferRect;
    std::vector<uint32_t> m_vramWriteBuffer;
    std::vector<uint32_t> m_vramReadBuffer;

    std::vector<Vertex> m_vertices;
    std::array<uint32_t, 16> m_cmdFIFO;
    OpenGL::Rect m_displayArea;
    OpenGL::Rect m_scissorBox;
    int m_drawAreaLeft, m_drawAreaRight, m_drawAreaTop, m_drawAreaBottom;

    OpenGL::ivec2 m_drawingOffset;
    // Clear colour used in the debugger
    OpenGL::vec3 m_clearColour = OpenGL::vec3({0.f, 0.f, 0.f});
    // Specifies how and whether to fill renderer polygons
    OpenGL::FillMode m_polygonMode = OpenGL::FillPoly;
    bool m_multisampled = false;
    int m_polygonModeIndex = 0;

    GLint m_drawingOffsetLoc;

    int m_FIFOIndex;
    int m_cmd;

    int m_vertexCount = 0;
    int m_remainingWords = 0;
    int m_lastCommandHash = 0;
    bool m_haveCommand = false;
    bool m_syncVRAM;
    uint32_t m_rectTexpage = 0; // Rects have their own texpage settings
    uint32_t m_vramReadBufferSize = 0;
    uint32_t m_vramReadBufferIndex = 0;
    GP0Func m_cmdFuncs[256];

    void renderBatch();
    void clearVRAM(float r, float g, float b, float a = 1.0);
    void updateDrawArea();
    void updateDispArea();
    void setScissorArea();
    void changeProgram();

    enum class Texturing {
        None, Textured
    };

    enum class PolyType {
        Triangle, Quad
    };

    enum class RectSize {
        Variable, Rect1, Rect8, Rect16
    };

    enum class Shading {
        Flat, Gouraud
    };

    template <Shading shading, Texturing mode>
    void drawVertex(int index, int vertexSize) {
        uint32_t colour;
        if constexpr (shading == Shading::Flat) {
            colour = m_cmdFIFO[0];
        } else {
            colour = m_cmdFIFO[index * vertexSize];
        }

        /*
        if constexpr (mode == Texturing::Textured) {
            if constexpr (shading == Shading::Gouraud) {
                m_vertices[m_vertexCount].texpage = 
            } else {
            
            }
        }
        */

        const uint32_t pos = m_cmdFIFO[index * vertexSize + 1];
        m_vertices[m_vertexCount++] = Vertex(pos, colour);
    }

    template <PolyType type, Shading shading, Texturing mode = Texturing::None>
    void drawPoly() {
        int hash = 0;
        int vertexSize = 1; // Vertex size in words
        if constexpr (mode == Texturing::Textured) {
            hash |= 1;
            vertexSize++; // 1 word for each vert's UVs
        }

        if constexpr (shading == Shading::Gouraud) {
            vertexSize++; // 1 word for each vert's colour
        }

        if constexpr (type == PolyType::Triangle) {
            if (m_vertexCount + 3 >= vertexBufferSize) {
                renderBatch();
            }

            drawVertex<shading, mode>(0, vertexSize);
            drawVertex<shading, mode>(1, vertexSize);
            drawVertex<shading, mode>(2, vertexSize);
        } else if constexpr (type == PolyType::Quad) {
            if (m_vertexCount + 6 >= vertexBufferSize) {
                renderBatch();
            }

            drawVertex<shading, mode>(0, vertexSize);
            drawVertex<shading, mode>(1, vertexSize);
            drawVertex<shading, mode>(2, vertexSize);
            drawVertex<shading, mode>(1, vertexSize);
            drawVertex<shading, mode>(2, vertexSize);
            drawVertex<shading, mode>(3, vertexSize);
        }
    }

    template <RectSize size, Texturing mode = Texturing::None>
    void drawRect() {
        int height, width;

        const uint32_t colour = m_cmdFIFO[0];
        const uint32_t pos = m_cmdFIFO[1];

        // Sign extend vertices
        const int x = int(pos) << 21 >> 21;
        const int y = int(pos) << 5 >> 21;

        if constexpr (size == RectSize::Rect1) {
            width = height = 1;
        }
        else if constexpr (size == RectSize::Rect8) {
            width = height = 8;
        }
        else if constexpr (size == RectSize::Rect16) {
            width = height = 16;
        }
        else {
            uint32_t dimensions = mode == Texturing::None ? m_cmdFIFO[2] : m_cmdFIFO[3];
            width = dimensions & 0x3ff;
            height = (dimensions >> 16) & 0x1ff;
        }

        if (m_vertexCount + 6 >= vertexBufferSize) {
            renderBatch();
        }

        m_vertices[m_vertexCount++] = Vertex(x, y, colour);
        m_vertices[m_vertexCount++] = Vertex(x + width, y, colour);
        m_vertices[m_vertexCount++] = Vertex(x + width, y + height, colour);
        m_vertices[m_vertexCount++] = Vertex(x + width, y + height, colour);
        m_vertices[m_vertexCount++] = Vertex(x, y + height, colour);
        m_vertices[m_vertexCount++] = Vertex(x, y, colour);
    }

    // GP0/GP1 command funcs
    void initCommands();
    void startGP0Command(uint32_t commandWord);

    void cmdUnimplemented();
    void cmdClearTexCache();
    void cmdFillRect();
    void cmdCopyRectToVRAM();
    void cmdCopyRectFromVRAM();
    void cmdSetDrawMode();
    void cmdSetTexWindow();
    void cmdSetDrawAreaTopLeft();
    void cmdSetDrawAreaBottomRight();
    void cmdSetDrawOffset();
    void cmdSetDrawMask();
    void cmdNop();

    void theOminousTexturedQuad();
    void theOminousTexturedShadedQuad();
    void theOminousTexturedRect();
};
}  // namespace PCSX
