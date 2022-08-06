#include "gpu_opengl.h"
#include <cmath>

// The number of 32-bit parameters for each GP0 command (discounting the command word)
static constexpr int c_paramCount[256] = {
    //  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 00
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 10
    0x03, 0x03, 0x03, 0x03, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x04, 0x04, 0x08, 0x08, 0x08, 0x08,  // 20
    0x05, 0x05, 0x05, 0x05, 0x08, 0x08, 0x08, 0x08, 0x07, 0x07, 0x07, 0x07, 0x0B, 0x0B, 0x0B, 0x0B,  // 30
    0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05, 0x05,  // 40
    0x03, 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06, 0x06, 0x06, 0x08, 0x08, 0x08, 0x08,  // 50
    0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03, 0x03, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,  // 60
    0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02,  // 70
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,  // 80
    0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,  // 90
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // A0
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // B0
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // C0
    0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  // D0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // E0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // F0
};

void PCSX::OpenGL_GPU::startGP0Command(uint32_t commandWord) {
    const uint32_t cmd = commandWord >> 24;
    const int paramCount = c_paramCount[cmd];
    m_cmdFIFO[0] = commandWord;

    // Handle non-instant commands
    if (paramCount != 0) {
        m_cmd = cmd;
        m_FIFOIndex = 1;
        m_haveCommand = true;
        m_remainingWords = paramCount;
    } else {  // Handle instant commands, eg draw area setting
        const auto func = m_cmdFuncs[cmd];
        (*this.*func)();
    }
}

template <PCSX::OpenGL_GPU::Transparency setting>
void PCSX::OpenGL_GPU::setTransparency() {
    // Check if we had transparency previously disabled and it just got enabled or vice versa
    if (m_lastTransparency != setting) {
        renderBatch();
        if constexpr (setting == Transparency::Opaque) {
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
        m_lastBlendingMode = newBlendingMode;
        renderBatch();
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
            case 2:  //  B - F
                OpenGL::setBlendEquation(OpenGL::BlendEquation::ReverseSub, OpenGL::BlendEquation::Add);
                setBlendFactors(1.0, 1.0);
                break;
            case 3:  // B + F/4
                OpenGL::setBlendEquation(OpenGL::BlendEquation::Add);
                setBlendFactors(1.0, 0.25);
                break;
        }
    }
}

void PCSX::OpenGL_GPU::setBlendFactors(float destFactor, float sourceFactor) {
    if (m_blendFactors.x() != destFactor || m_blendFactors.y() != sourceFactor) {
        m_blendFactors.x() = destFactor;
        m_blendFactors.y() = sourceFactor;

        glUniform4f(m_blendFactorsLoc, destFactor, destFactor, destFactor, sourceFactor);
    }
}

template <PCSX::OpenGL_GPU::Shading shading, PCSX::OpenGL_GPU::Transparency transparency, int firstVertex>
void PCSX::OpenGL_GPU::drawTri() {
    if (m_vertexCount + 3 >= vertexBufferSize) renderBatch();

    // Only do transparency-related stuff for the first triangle of a quad
    if constexpr (firstVertex == 0) {
        setTransparency<transparency>();
        if constexpr (transparency == Transparency::Transparent) {
            setBlendingModeFromTexpage(m_rectTexpage);
        }
    }

    if constexpr (shading == Shading::Flat) {
        const uint32_t colour = m_cmdFIFO[0];
        m_vertices[m_vertexCount++] = Vertex(m_cmdFIFO[firstVertex + 1], colour);
        m_vertices[m_vertexCount++] = Vertex(m_cmdFIFO[firstVertex + 2], colour);
        m_vertices[m_vertexCount++] = Vertex(m_cmdFIFO[firstVertex + 3], colour);
    } else {
        for (int i = firstVertex; i < firstVertex + 3; i++) {
            const uint32_t colour = m_cmdFIFO[i * 2];
            const uint32_t pos = m_cmdFIFO[i * 2 + 1];
            m_vertices[m_vertexCount++] = Vertex(pos, colour);
        }
    }
}

template <PCSX::OpenGL_GPU::Shading shading, PCSX::OpenGL_GPU::Transparency transparency>
void PCSX::OpenGL_GPU::drawQuad() {
    drawTri<shading, transparency, 0>();
    drawTri<shading, transparency, 1>();
}

template <PCSX::OpenGL_GPU::Shading shading, PCSX::OpenGL_GPU::Transparency transparency, int firstVertex>
void PCSX::OpenGL_GPU::drawTriTextured() {
    if (m_vertexCount + 3 >= vertexBufferSize) renderBatch();

    // Only do transparency-related stuff for the first triangle of a quad
    if constexpr (firstVertex == 0) {
        setTransparency<transparency>();
        if constexpr (transparency == Transparency::Transparent) {
            const uint32_t texpage =
                (shading == Shading::RawTexture || shading == Shading::TextureBlendFlat) ? m_cmdFIFO[4] : m_cmdFIFO[5];
            setBlendingModeFromTexpage(texpage >> 16);
        }
    }

    if constexpr (shading == Shading::RawTexture || shading == Shading::TextureBlendFlat) {
        const uint32_t colour = shading == Shading::RawTexture ? c_rawTextureBlendColour : m_cmdFIFO[0];
        const uint32_t clut = m_cmdFIFO[2] >> 16;
        const uint32_t texpage = (m_cmdFIFO[4] >> 16) & 0x3fff;

        for (int i = firstVertex; i < firstVertex + 3; i++) {
            const uint32_t pos = m_cmdFIFO[i * 2 + 1];
            const auto uv = m_cmdFIFO[i * 2 + 2];
            m_vertices[m_vertexCount++] = Vertex(pos, colour, clut, texpage, uv);
        }
    } else {
        const uint32_t clut = m_cmdFIFO[2] >> 16;
        const uint32_t texpage = (m_cmdFIFO[5] >> 16) & 0x3fff;

        for (int i = firstVertex; i < firstVertex + 3; i++) {
            const auto colour = shading == Shading::TextureBlendGouraud ? m_cmdFIFO[i * 3] : c_rawTextureBlendColour;
            const auto pos = m_cmdFIFO[i * 3 + 1];
            const auto uv = m_cmdFIFO[i * 3 + 2];
            m_vertices[m_vertexCount++] = Vertex(pos, colour, clut, texpage, uv);
        }
    }
}

template <PCSX::OpenGL_GPU::Shading shading, PCSX::OpenGL_GPU::Transparency transparency>
void PCSX::OpenGL_GPU::drawQuadTextured() {
    drawTriTextured<shading, transparency, 0>();
    drawTriTextured<shading, transparency, 1>();
}

template <PCSX::OpenGL_GPU::RectSize size, PCSX::OpenGL_GPU::Transparency transparency>
void PCSX::OpenGL_GPU::drawRect() {
    if (m_vertexCount + 6 >= vertexBufferSize) {
        renderBatch();
    }

    setTransparency<transparency>();
    if constexpr (transparency == Transparency::Transparent) {
        setBlendingModeFromTexpage(m_rectTexpage);
    }

    int height, width;

    const uint32_t colour = m_cmdFIFO[0];
    const uint32_t pos = m_cmdFIFO[1];

    // Sign extend vertices
    const int x = int(pos) << 21 >> 21;
    const int y = int(pos) << 5 >> 21;

    if constexpr (size == RectSize::Rect1) {
        width = height = 1;
    } else if constexpr (size == RectSize::Rect8) {
        width = height = 8;
    } else if constexpr (size == RectSize::Rect16) {
        width = height = 16;
    } else {
        uint32_t dimensions = m_cmdFIFO[2];
        width = dimensions & 0x3ff;
        height = (dimensions >> 16) & 0x1ff;
    }

    m_vertices[m_vertexCount++] = Vertex(x, y, colour);
    m_vertices[m_vertexCount++] = Vertex(x + width, y, colour);
    m_vertices[m_vertexCount++] = Vertex(x + width, y + height, colour);
    m_vertices[m_vertexCount++] = Vertex(x + width, y + height, colour);
    m_vertices[m_vertexCount++] = Vertex(x, y + height, colour);
    m_vertices[m_vertexCount++] = Vertex(x, y, colour);
}

template <PCSX::OpenGL_GPU::RectSize size, PCSX::OpenGL_GPU::Shading shading,
          PCSX::OpenGL_GPU::Transparency transparency>
void PCSX::OpenGL_GPU::drawRectTextured() {
    if (m_vertexCount + 6 >= vertexBufferSize) {
        renderBatch();
    }

    setTransparency<transparency>();
    if constexpr (transparency == Transparency::Transparent) {
        setBlendingModeFromTexpage(m_rectTexpage);
    }

    int height, width;

    const uint32_t colour = shading == Shading::RawTexture ? c_rawTextureBlendColour : m_cmdFIFO[0];
    const uint32_t pos = m_cmdFIFO[1];

    const uint32_t clut = m_cmdFIFO[2] >> 16;
    const uint32_t uv = m_cmdFIFO[2] & 0xffff;
    const uint32_t u = uv & 0xff;
    const uint32_t v = uv >> 8;
    const uint32_t texpage = m_rectTexpage;

    // Sign extend vertices
    const int x = int(pos) << 21 >> 21;
    const int y = int(pos) << 5 >> 21;

    if constexpr (size == RectSize::Rect1) {
        width = height = 1;
    } else if constexpr (size == RectSize::Rect8) {
        width = height = 8;
    } else if constexpr (size == RectSize::Rect16) {
        width = height = 16;
    } else {
        uint32_t dimensions = m_cmdFIFO[3];
        width = dimensions & 0x3ff;
        height = (dimensions >> 16) & 0x1ff;
    }

    m_vertices[m_vertexCount++] = Vertex(x, y, colour, clut, texpage, u, v);
    m_vertices[m_vertexCount++] = Vertex(x + width, y, colour, clut, texpage, u + width, v);
    m_vertices[m_vertexCount++] = Vertex(x + width, y + height, colour, clut, texpage, u + width, v + height);
    m_vertices[m_vertexCount++] = Vertex(x + width, y + height, colour, clut, texpage, u + width, v + height);
    m_vertices[m_vertexCount++] = Vertex(x, y + height, colour, clut, texpage, u, v + height);
    m_vertices[m_vertexCount++] = Vertex(x, y, colour, clut, texpage, u, v);
}

template <PCSX::OpenGL_GPU::Shading shading, PCSX::OpenGL_GPU::Transparency transparency>
void PCSX::OpenGL_GPU::drawLine() {
    setTransparency<transparency>();
    if constexpr (transparency == Transparency::Transparent) {
        setBlendingModeFromTexpage(m_rectTexpage);
    }

    LinePoint p1, p2;
    if constexpr (shading == Shading::Flat) {
        p1.colour = m_cmdFIFO[0];
        p1.coords = m_cmdFIFO[1];

        p2.colour = m_cmdFIFO[0];
        p2.coords = m_cmdFIFO[2];
    } else {
        p1.colour = m_cmdFIFO[0];
        p1.coords = m_cmdFIFO[1];

        p2.colour = m_cmdFIFO[2];
        p2.coords = m_cmdFIFO[3];
    }

    drawLineInternal(p1, p2);
}

void PCSX::OpenGL_GPU::drawLineInternal(const LinePoint& p1, const LinePoint& p2) {
    if (m_vertexCount + 6 >= vertexBufferSize) {
        renderBatch();
    }

    const auto getPos = [](const LinePoint& point) -> std::pair<int32_t, int32_t> {
        int32_t x = int32_t(point.coords) << 21 >> 21;
        int32_t y = int32_t(point.coords) << 5 >> 21;
        return {x, y};
    };

    auto [x1, y1] = getPos(p1);
    auto [x2, y2] = getPos(p2);

    const int32_t dx = x2 - x1;
    const int32_t dy = y2 - y1;

    const auto absDx = std::abs(dx);
    const auto absDy = std::abs(dy);

    // Both vertices coincide, render 1x1 rectangle with the colour and coords of v1
    if (dx == 0 && dy == 0) {
        m_vertices[m_vertexCount++] = Vertex(x1, y1, p1.colour);
        m_vertices[m_vertexCount++] = Vertex(x1 + 1, y1, p1.colour);
        m_vertices[m_vertexCount++] = Vertex(x1 + 1, y1 + 1, p1.colour);

        m_vertices[m_vertexCount++] = Vertex(x1 + 1, y1 + 1, p1.colour);
        m_vertices[m_vertexCount++] = Vertex(x1, y1 + 1, p1.colour);
        m_vertices[m_vertexCount++] = Vertex(x1, y1, p1.colour);
    } else {
        int xOffset, yOffset;
        if (absDx > absDy) { // x-major line
            xOffset = 0;
            yOffset = 1;

            // Align line depending on whether dx is positive or not
            dx > 0 ? x2++ : x1++;
        } else { // y-major line
            xOffset = 1;
            yOffset = 0;

            // Align line depending on whether dy is positive or not
            dy > 0 ? y2++ : y1++;
        }

        m_vertices[m_vertexCount++] = Vertex(x1, y1, p1.colour);
        m_vertices[m_vertexCount++] = Vertex(x2, y2, p2.colour);
        m_vertices[m_vertexCount++] = Vertex(x2 + xOffset, y2 + yOffset, p2.colour);

        m_vertices[m_vertexCount++] = Vertex(x2 + xOffset, y2 + yOffset, p2.colour);
        m_vertices[m_vertexCount++] = Vertex(x1 + xOffset, y1 + yOffset, p1.colour);
        m_vertices[m_vertexCount++] = Vertex(x1, y1, p1.colour);
    }
}

void PCSX::OpenGL_GPU::initCommands() {
    for (int i = 0; i < 256; i++) {
        m_cmdFuncs[i] = &OpenGL_GPU::cmdUnimplemented;
    }

    m_cmdFuncs[0x00] = &OpenGL_GPU::cmdNop;
    m_cmdFuncs[0x01] = &OpenGL_GPU::cmdClearTexCache;
    m_cmdFuncs[0x02] = &OpenGL_GPU::cmdFillRect;
    m_cmdFuncs[0x1F] = &OpenGL_GPU::cmdRequestIRQ;
    m_cmdFuncs[0xE1] = &OpenGL_GPU::cmdSetDrawMode;
    m_cmdFuncs[0xE2] = &OpenGL_GPU::cmdSetTexWindow;
    m_cmdFuncs[0xE3] = &OpenGL_GPU::cmdSetDrawAreaTopLeft;
    m_cmdFuncs[0xE4] = &OpenGL_GPU::cmdSetDrawAreaBottomRight;
    m_cmdFuncs[0xE5] = &OpenGL_GPU::cmdSetDrawOffset;
    m_cmdFuncs[0xE6] = &OpenGL_GPU::cmdSetDrawMask;

    m_cmdFuncs[0x20] = &OpenGL_GPU::drawTri<Shading::Flat, Transparency::Opaque>;
    m_cmdFuncs[0x22] = &OpenGL_GPU::drawTri<Shading::Flat, Transparency::Transparent>;
    m_cmdFuncs[0x24] = &OpenGL_GPU::drawTriTextured<Shading::TextureBlendFlat, Transparency::Opaque>;
    m_cmdFuncs[0x25] = &OpenGL_GPU::drawTriTextured<Shading::RawTexture, Transparency::Opaque>;
    m_cmdFuncs[0x26] = &OpenGL_GPU::drawTriTextured<Shading::TextureBlendFlat, Transparency::Transparent>;
    m_cmdFuncs[0x27] = &OpenGL_GPU::drawTriTextured<Shading::RawTexture, Transparency::Transparent>;

    m_cmdFuncs[0x28] = &OpenGL_GPU::drawQuad<Shading::Flat, Transparency::Opaque>;
    m_cmdFuncs[0x29] = m_cmdFuncs[0x28]; // Duplicate
    m_cmdFuncs[0x2A] = &OpenGL_GPU::drawQuad<Shading::Flat, Transparency::Transparent>;
    m_cmdFuncs[0x2C] = &OpenGL_GPU::drawQuadTextured<Shading::TextureBlendFlat, Transparency::Opaque>;
    m_cmdFuncs[0x2D] = &OpenGL_GPU::drawQuadTextured<Shading::RawTexture, Transparency::Opaque>;
    m_cmdFuncs[0x2E] = &OpenGL_GPU::drawQuadTextured<Shading::TextureBlendFlat, Transparency::Transparent>;
    m_cmdFuncs[0x2F] = &OpenGL_GPU::drawQuadTextured<Shading::RawTexture, Transparency::Transparent>;
    
    m_cmdFuncs[0x30] = &OpenGL_GPU::drawTri<Shading::Gouraud, Transparency::Opaque>;
    m_cmdFuncs[0x32] = &OpenGL_GPU::drawTri<Shading::Gouraud, Transparency::Transparent>;
    m_cmdFuncs[0x34] = &OpenGL_GPU::drawTriTextured<Shading::TextureBlendGouraud, Transparency::Opaque>;
    m_cmdFuncs[0x35] = &OpenGL_GPU::drawTriTextured<Shading::RawTextureGouraud, Transparency::Opaque>;
    m_cmdFuncs[0x36] = &OpenGL_GPU::drawTriTextured<Shading::TextureBlendGouraud, Transparency::Transparent>;
    
    m_cmdFuncs[0x38] = &OpenGL_GPU::drawQuad<Shading::Gouraud, Transparency::Opaque>;
    m_cmdFuncs[0x3A] = &OpenGL_GPU::drawQuad<Shading::Gouraud, Transparency::Transparent>;
    m_cmdFuncs[0x3B] = m_cmdFuncs[0x3A]; // Duplicate

    m_cmdFuncs[0x3C] = &OpenGL_GPU::drawQuadTextured<Shading::TextureBlendGouraud, Transparency::Opaque>;
    m_cmdFuncs[0x3D] = &OpenGL_GPU::drawQuadTextured<Shading::RawTextureGouraud, Transparency::Opaque>;
    m_cmdFuncs[0x3E] = &OpenGL_GPU::drawQuadTextured<Shading::TextureBlendGouraud, Transparency::Transparent>;
    m_cmdFuncs[0x3F] = &OpenGL_GPU::drawQuadTextured<Shading::RawTextureGouraud, Transparency::Transparent>;

    m_cmdFuncs[0x40] = &OpenGL_GPU::drawLine<Shading::Flat, Transparency::Opaque>;
    m_cmdFuncs[0x42] = &OpenGL_GPU::drawLine<Shading::Flat, Transparency::Transparent>;
    m_cmdFuncs[0x50] = &OpenGL_GPU::drawLine<Shading::Gouraud, Transparency::Opaque>;
    m_cmdFuncs[0x52] = &OpenGL_GPU::drawLine<Shading::Gouraud, Transparency::Transparent>;

    m_cmdFuncs[0x60] = &OpenGL_GPU::drawRect<RectSize::Variable, Transparency::Opaque>;
    m_cmdFuncs[0x62] = &OpenGL_GPU::drawRect<RectSize::Variable, Transparency::Transparent>;
    m_cmdFuncs[0x64] =
        &OpenGL_GPU::drawRectTextured<RectSize::Variable, Shading::TextureBlendFlat, Transparency::Opaque>;
    m_cmdFuncs[0x65] =
        &OpenGL_GPU::drawRectTextured<RectSize::Variable, Shading::RawTexture, Transparency::Opaque>;
    m_cmdFuncs[0x66] =
        &OpenGL_GPU::drawRectTextured<RectSize::Variable, Shading::TextureBlendFlat, Transparency::Transparent>;
    m_cmdFuncs[0x67] =
        &OpenGL_GPU::drawRectTextured<RectSize::Variable, Shading::RawTexture, Transparency::Transparent>;

    m_cmdFuncs[0x68] = &OpenGL_GPU::drawRect<RectSize::Rect1, Transparency::Opaque>;
    m_cmdFuncs[0x70] = &OpenGL_GPU::drawRect<RectSize::Rect8, Transparency::Opaque>;
    m_cmdFuncs[0x74] = &OpenGL_GPU::drawRectTextured<RectSize::Rect8, Shading::TextureBlendFlat, Transparency::Opaque>;
    m_cmdFuncs[0x75] = &OpenGL_GPU::drawRectTextured<RectSize::Rect8, Shading::RawTexture, Transparency::Opaque>;
    m_cmdFuncs[0x7C] = &OpenGL_GPU::drawRectTextured<RectSize::Rect16, Shading::TextureBlendFlat, Transparency::Opaque>;
    m_cmdFuncs[0x7D] = &OpenGL_GPU::drawRectTextured<RectSize::Rect16, Shading::RawTexture, Transparency::Opaque>;

    m_cmdFuncs[0xA0] = &OpenGL_GPU::cmdCopyRectToVRAM;
    m_cmdFuncs[0xC0] = &OpenGL_GPU::cmdCopyRectFromVRAM;
}

void PCSX::OpenGL_GPU::cmdNop() {}
void PCSX::OpenGL_GPU::cmdClearTexCache() {
    renderBatch();
    m_syncVRAM = true;
}

void PCSX::OpenGL_GPU::cmdSetDrawMode() {
    m_rectTexpage = m_cmdFIFO[0] & 0x3fff;
}

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

void PCSX::OpenGL_GPU::cmdSetTexWindow() {
    setTexWindow(m_cmdFIFO[0]);
}

void PCSX::OpenGL_GPU::cmdSetDrawMask() {
    //PCSX::g_system->printf("Unimplemented set draw mask command: %08X\n", m_cmdFIFO[0]);
}

void PCSX::OpenGL_GPU::cmdSetDrawAreaTopLeft() {
    const uint32_t word = m_cmdFIFO[0];

    m_drawAreaLeft = word & 0x3ff;
    m_drawAreaTop = (word >> 10) & 0x1ff;
    updateDrawArea();
}

void PCSX::OpenGL_GPU::cmdSetDrawAreaBottomRight() {
    const uint32_t word = m_cmdFIFO[0];

    m_drawAreaRight = word & 0x3ff;
    m_drawAreaBottom = (word >> 10) & 0x1ff;
    updateDrawArea();
}

void PCSX::OpenGL_GPU::setDrawOffset(uint32_t cmd) { 
    m_updateDrawOffset = false;
    m_lastDrawOffsetSetting = cmd & 0x3fffff; // Discard the bits we don't care about
    
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

void PCSX::OpenGL_GPU::cmdSetDrawOffset() {
    renderBatch();
    const uint32_t word = m_cmdFIFO[0] & 0x3fffff; // Discard the bits we don't care about

    // Queue a draw offset update if it changed
    if (word != m_lastDrawOffsetSetting) {
        m_updateDrawOffset = true;
        m_lastDrawOffsetSetting = word;
    }
}

void PCSX::OpenGL_GPU::cmdFillRect() {
    renderBatch();
    const auto colour = m_cmdFIFO[0] & 0xffffff;
    const float r = float(colour & 0xff) / 255.f;
    const float g = float((colour >> 8) & 0xff) / 255.f;
    const float b = float((colour >> 16) & 0xff) / 255.f;

    OpenGL::setClearColor(r, g, b, 1.f);
    const uint32_t x0 = m_cmdFIFO[1] & 0xffff;
    const uint32_t y0 = m_cmdFIFO[1] >> 16;
    const uint32_t width = m_cmdFIFO[2] & 0xffff;
    const uint32_t height = m_cmdFIFO[2] >> 16;

    OpenGL::setScissor(x0, y0, width, height);
    OpenGL::clearColor();
    setScissorArea();
}

void PCSX::OpenGL_GPU::cmdCopyRectToVRAM() {
    m_writingMode = TransferMode::VRAMTransfer;
    m_haveCommand = true;
    const uint32_t coords = m_cmdFIFO[1];
    const uint32_t res = m_cmdFIFO[2];

    uint32_t width = res & 0xffff;
    uint32_t height = res >> 16;

    width = ((width - 1) & 0x3ff) + 1;
    height = ((height - 1) & 0x1ff) + 1;

    // TODO: Sanitize this
    m_vramTransferRect.x = coords & 0x3ff;
    m_vramTransferRect.y = (coords >> 16) & 0x1ff;
    m_vramTransferRect.width = width;
    m_vramTransferRect.height = height;

    // The size of the texture in 16-bit pixels. If the number is odd, force align it up
    const uint32_t size = ((width * height) + 1) & ~1;
    m_remainingWords = size / 2;
}

void PCSX::OpenGL_GPU::cmdCopyRectFromVRAM() {
    renderBatch();
    const uint32_t coords = m_cmdFIFO[1];
    const uint32_t res = m_cmdFIFO[2];
    // TODO: Sanitize this
    const auto x = coords & 0x3ff;
    const auto y = (coords >> 16) & 0x1ff;

    uint32_t width = res & 0xffff;
    uint32_t height = res >> 16;

    width = ((width - 1) & 0x3ff) + 1;
    height = ((height - 1) & 0x1ff) + 1;

    // The size of the texture in 16-bit pixels. If the number is odd, force align it up
    const uint32_t size = ((width * height) + 1) & ~1;

    m_readingMode = TransferMode::VRAMTransfer;
    m_vramReadBufferSize = size / 2;
    m_vramReadBufferIndex = 0;

    if (!m_multisampled) {
        glReadPixels(x, y, width, height, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, &m_vramReadBuffer[0]);
    } else {
        // We can't read from multisampled textures as they contain more than just our pixels.
        // So we blit the part of the texture that we want to our non-MSAA texture, then read that

        m_fboNoMSAA.bind(OpenGL::DrawFramebuffer);
        glBlitFramebuffer(x, y, x + width, y + height, x, y, x + width, y + height, GL_COLOR_BUFFER_BIT, GL_LINEAR);
        m_fboNoMSAA.bind(OpenGL::ReadFramebuffer);
        glReadPixels(x, y, width, height, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, &m_vramReadBuffer[0]);
        m_fbo.bind(OpenGL::DrawAndReadFramebuffer);
    }
}

void PCSX::OpenGL_GPU::cmdUnimplemented() {
    //PCSX::g_system->printf("Unknown GP0 command: %02X\n", m_cmdFIFO[0] >> 24);
}
