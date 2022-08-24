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
#include "gui/widgets/shader-editor.h"
#include "support/opengl.h"

namespace PCSX {
class OpenGL_GPU final : public GPU {
    // Interface functions
    int initBackend(GUI *) override;
    int shutdown() override;
    void readDataMem(uint32_t *dest, int size) override;
    uint32_t readStatusInternal() override;
    void writeDataMem(uint32_t *source, int size) override;
    void writeStatusInternal(uint32_t value) override;
    int32_t dmaChain(uint32_t *baseAddrL, uint32_t addr) override;
    void setOpenGLContext() override;
    void vblank() override;
    bool configure() override;
    void debug() override;

    void setDither(int setting) override { m_useDither = setting; }
    void clearVRAM() override;
    void reset() override;
    GLuint getVRAMTexture() override;
    void setLinearFiltering() override;
    Slice getVRAM() override;
    void partialUpdateVRAM(int x, int y, int w, int h, const uint16_t *pixels) override;
    void restoreStatus(uint32_t status) { m_gpustat = status; }

  private:
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

        Vertex() : Vertex(0, 0, 0) {}

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

        Vertex(uint32_t position, uint32_t col, uint16_t clut, uint16_t texpage, uint32_t texcoords)
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

    // One of the 2 points in a line
    struct LinePoint {
        uint32_t coords;
        uint32_t colour;
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

    OpenGL::Program m_program;
    OpenGL::VertexArray m_vao;
    OpenGL::VertexBuffer m_vbo;
    OpenGL::Framebuffer m_fbo;
    OpenGL::Texture m_vramTexture;
    OpenGL::Texture m_blankTexture;  // Black texture to display when the display is off

    // We need non-MSAA copies of our texture & FBO when using multisampling
    OpenGL::Texture m_vramTextureNoMSAA;
    OpenGL::Framebuffer m_fboNoMSAA;
    Widgets::ShaderEditor m_shaderEditor = {"hw-renderer"};

    // For CPU->VRAM texture transfers
    OpenGL::Texture m_sampleTexture;
    OpenGL::Rect m_vramTransferRect;
    std::vector<uint32_t> m_vramWriteBuffer;
    std::vector<uint32_t> m_vramReadBuffer;

    std::vector<Vertex> m_vertices;
    std::array<uint32_t, 16> m_cmdFIFO;
    OpenGL::Rect m_scissorBox;
    int m_drawAreaLeft, m_drawAreaRight, m_drawAreaTop, m_drawAreaBottom;

    OpenGL::ivec2 m_drawingOffset;
    // Clear colour used in the debugger
    OpenGL::vec3 m_clearColour = OpenGL::vec3({0.f, 0.f, 0.f});
    // Specifies how and whether to fill renderer polygons
    OpenGL::FillMode m_polygonMode = OpenGL::FillPoly;
    // x: The factor to multiply the destination (framebuffer) colour with
    // y: The factor to multiply the source colour with
    OpenGL::vec2 m_blendFactors;

    bool m_multisampled = false;
    int m_polygonModeIndex = 0;

    GLint m_drawingOffsetLoc;
    GLint m_texWindowLoc;
    GLint m_blendFactorsLoc;
    GLint m_blendFactorsIfOpaqueLoc;
    // The handle of the texture to actually display on screen.
    // The handle of either m_vramTexture, m_vramTextureNoMSAA or m_blankTexture
    // Depending on whether the display and MSAA are enabled
    GLuint m_displayTexture;

    int m_FIFOIndex;
    int m_cmd;

    int m_vertexCount = 0;
    int m_remainingWords = 0;
    bool m_haveCommand = false;
    bool m_updateDrawOffset = false;
    bool m_syncVRAM = true;
    bool m_drawnStuff = false;
    uint32_t m_rectTexpage = 0;  // Rects have their own texpage settings
    uint32_t m_vramReadBufferSize = 0;
    uint32_t m_vramReadBufferIndex = 0;
    uint32_t m_lastTexwindowSetting = 0;
    uint32_t m_lastDrawOffsetSetting = 0;
    uint32_t m_drawMode;

    GP0Func m_cmdFuncs[256];

    void renderBatch();
    void clearVRAM(float r, float g, float b, float a = 1.0);
    void updateDrawArea();
    void setScissorArea();
    void setDrawOffset(uint32_t cmd);
    void setTexWindow(uint32_t cmd);
    void setTexWindowUnchecked(uint32_t cmd);
    void setDisplayEnable(bool setting);

    enum class RectSize { Variable, Rect1, Rect8, Rect16 };

    // For untextured primitives, there's flat and gouraud shading.
    // For textured primitives, RawTexture and RawTextureGouraud work the same way, except the latter has unused colour
    // parameters RawTextureGouraud is used a lot by some games, like Castlevania TextureBlendFlat is texture blending
    // with a flat colour, TextureBlendGouraud is texture blending with a gouraud shaded colour
    enum class GLShading { Flat, Gouraud, RawTexture, RawTextureGouraud, TextureBlendFlat, TextureBlendGouraud };

    enum class Transparency { Opaque, Transparent };

    // 0: Back / 2 + Front / 2
    // 1: Back + Front
    // 2: Back - Front
    // 3: Back + Front / 4
    // -1: Transparency was previously disabled
    int m_lastBlendingMode = -1;
    Transparency m_lastTransparency;

    // We can emulate raw texture primitives as primitives with texture blending enabled
    // And 0x808080 as the blend colour
    static constexpr uint32_t c_rawTextureBlendColour = 0x808080;

    template <GLShading shading, Transparency transparency, int firstVertex = 0>
    void drawTri();

    template <GLShading shading, Transparency transparency>
    void drawQuad();

    template <GLShading shading, Transparency transparency, int firstVertex = 0>
    void drawTriTextured();

    template <GLShading shading, Transparency transparency>
    void drawQuadTextured();

    template <RectSize size, Transparency transparency>
    void drawRect();

    template <RectSize size, GLShading shading, Transparency transparency>
    void drawRectTextured();

    template <GLShading shading, Transparency transparency>
    void drawLine();

    void drawLineInternal(const LinePoint &p1, const LinePoint &p2);

    template <Transparency setting>
    void setTransparency();

    void setBlendingModeFromTexpage(uint32_t texpage);
    void setBlendFactors(float sourceFactor, float destFactor);

    // GP0/GP1 command funcs
    void initCommands();
    void startGP0Command(uint32_t commandWord);

    void cmdUnimplemented();
    void cmdClearTexCache();
    void cmdFillRect();
    void cmdCopyRectToVRAM();
    void cmdCopyRectFromVRAM();
    void cmdCopyRectVRAMToVRAM();
    void cmdRequestIRQ() { requestIRQ1(); }
    void cmdSetDrawMode();
    void cmdSetTexWindow();
    void cmdSetDrawAreaTopLeft();
    void cmdSetDrawAreaBottomRight();
    void cmdSetDrawOffset();
    void cmdSetDrawMask();
    void cmdNop();

    void write0(FastFill *) override;

    void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *) override;

    void write0(Line<Shading::Flat, LineType::Simple, Blend::Off> *) override;
    void write0(Line<Shading::Flat, LineType::Simple, Blend::Semi> *) override;
    void write0(Line<Shading::Flat, LineType::Poly, Blend::Off> *) override;
    void write0(Line<Shading::Flat, LineType::Poly, Blend::Semi> *) override;
    void write0(Line<Shading::Gouraud, LineType::Simple, Blend::Off> *) override;
    void write0(Line<Shading::Gouraud, LineType::Simple, Blend::Semi> *) override;
    void write0(Line<Shading::Gouraud, LineType::Poly, Blend::Off> *) override;
    void write0(Line<Shading::Gouraud, LineType::Poly, Blend::Semi> *) override;

    void write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::Off> *) override;
    void write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::Off> *) override;
    void write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::On> *) override;
    void write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::On> *) override;
    void write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::On> *) override;
    void write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::On> *) override;
    void write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::On> *) override;
    void write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::On> *) override;

    void write0(BlitVramVram *) override;

    void write0(TPage *) override;
    void write0(TWindow *) override;
    void write0(DrawingAreaStart *) override;
    void write0(DrawingAreaEnd *) override;
    void write0(DrawingOffset *) override;
    void write0(MaskBit *) override;
};

}  // namespace PCSX
