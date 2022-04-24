#include "gpu_opengl.h"

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

void PCSX::OpenGL_GPU::initCommands() {
    for (int i = 0; i < 256; i++) {
        m_cmdFuncs[i] = &OpenGL_GPU::cmdUnimplemented;
    }

    m_cmdFuncs[0x00] = &OpenGL_GPU::cmdNop;
    m_cmdFuncs[0x01] = &OpenGL_GPU::cmdClearTexCache;
    m_cmdFuncs[0x02] = &OpenGL_GPU::cmdFillRect;
    m_cmdFuncs[0xE1] = &OpenGL_GPU::cmdSetDrawMode;
    m_cmdFuncs[0xE2] = &OpenGL_GPU::cmdSetTexWindow;
    m_cmdFuncs[0xE3] = &OpenGL_GPU::cmdSetDrawAreaTopLeft;
    m_cmdFuncs[0xE4] = &OpenGL_GPU::cmdSetDrawAreaBottomRight;
    m_cmdFuncs[0xE5] = &OpenGL_GPU::cmdSetDrawOffset;
    m_cmdFuncs[0xE6] = &OpenGL_GPU::cmdSetDrawMask;

    m_cmdFuncs[0x20] = &OpenGL_GPU::drawPoly<PolyType::Triangle, Shading::Flat, Texturing::None>;
    m_cmdFuncs[0x22] = &OpenGL_GPU::drawPoly<PolyType::Triangle, Shading::Flat, Texturing::None>;  // TODO: Transparency
    m_cmdFuncs[0x28] = &OpenGL_GPU::drawPoly<PolyType::Quad, Shading::Flat, Texturing::None>;

    //m_cmdFuncs[0x2C] = &OpenGL_GPU::drawPoly<PolyType::Quad, Shading::Flat, Texturing::Textured>;  // TODO: Blending
    m_cmdFuncs[0x2C] = &OpenGL_GPU::theOminousTexturedQuad;
    m_cmdFuncs[0x2D] = &OpenGL_GPU::drawPoly<PolyType::Quad, Shading::Flat, Texturing::Textured>;
    m_cmdFuncs[0x2F] = &OpenGL_GPU::drawPoly<PolyType::Quad, Shading::Flat, Texturing::Textured>; // TODO: Transparency
    
    m_cmdFuncs[0x30] = &OpenGL_GPU::drawPoly<PolyType::Triangle, Shading::Gouraud, Texturing::None>;
    m_cmdFuncs[0x38] = &OpenGL_GPU::drawPoly<PolyType::Quad, Shading::Gouraud, Texturing::None>;

    m_cmdFuncs[0x60] = &OpenGL_GPU::drawRect<RectSize::Variable, Texturing::None>;
    m_cmdFuncs[0x65] = &OpenGL_GPU::drawRect<RectSize::Variable, Texturing::Textured>;
    m_cmdFuncs[0x68] = &OpenGL_GPU::drawRect<RectSize::Rect1, Texturing::None>;

    m_cmdFuncs[0xA0] = &OpenGL_GPU::cmdCopyRectToVRAM;
    m_cmdFuncs[0xC0] = &OpenGL_GPU::cmdCopyRectFromVRAM;
}

void PCSX::OpenGL_GPU::cmdNop() {}
void PCSX::OpenGL_GPU::cmdClearTexCache() {
    //  Refresh our sample texture when the texture cache is flushed
    m_sampleTexture.bind();
    glCopyTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 0, 0, vramWidth, vramHeight);
}

void PCSX::OpenGL_GPU::cmdSetDrawMode() {
    PCSX::g_system->printf("Unimplemented set draw mode command: %08X\n", m_cmdFIFO[0]);
}

void PCSX::OpenGL_GPU::cmdSetTexWindow() {
    PCSX::g_system->printf("Unimplemented set texture window command: %08X\n", m_cmdFIFO[0]);
}

void PCSX::OpenGL_GPU::cmdSetDrawMask() {
    PCSX::g_system->printf("Unimplemented set draw mask command: %08X\n", m_cmdFIFO[0]);
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

void PCSX::OpenGL_GPU::cmdSetDrawOffset() {
    renderBatch();
    const uint32_t word = m_cmdFIFO[0];

    // Offset is a signed number in [-1024, 1023]
    const auto offsetX = (int32_t)word << 21 >> 21;
    const auto offsetY = (int32_t)word << 10 >> 21;

    m_drawingOffset.x() = offsetX;
    m_drawingOffset.y() = offsetY;

    // The 0.5 offsets help fix some holes in rendering, in places like the PS logo
    // TODO: This might not work when upscaling?
    float adjustedOffsets[2] = {static_cast<float>(offsetX) + 0.5f, static_cast<float>(offsetY) - 0.5f};
    glUniform2fv(m_drawingOffsetLoc, 1, adjustedOffsets);
}

void PCSX::OpenGL_GPU::cmdFillRect() {
    const auto colour = m_cmdFIFO[0] & 0xffffff;
    const float r = float(colour & 0xff) / 255.f;
    const float g = float((colour >> 8) & 0xff) / 255.f;
    const float b = float((colour >> 16) & 0xff) / 255.f;

    OpenGL::setClearColor(r, g, b, 1.f);
    const uint32_t x0 = m_cmdFIFO[1] & 0xffff;
    const uint32_t y0 = m_cmdFIFO[1] >> 16;
    const uint32_t width = m_cmdFIFO[2] & 0xffff;
    const uint32_t height = m_cmdFIFO[2] >> 16;

    renderBatch();
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
    glReadPixels(x, y, width, height, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, &m_vramReadBuffer[0]);
}

// Command 2C temp stub
void PCSX::OpenGL_GPU::theOminousTexturedQuad() {
    renderBatch();
    const uint32_t colour = m_cmdFIFO[0];
    const uint32_t clut = m_cmdFIFO[2] >> 16;
    const uint32_t texpage = m_cmdFIFO[4] >> 16;

    glUniform1i(m_texturedLoc, 1);
    for (int i = 0; i < 3; i++) {
        const auto pos = m_cmdFIFO[i * 2 + 1];
        const auto texcoord = m_cmdFIFO[i * 2 + 2];

        m_vertices[m_vertexCount] = Vertex(pos, colour, clut, texpage, texcoord);
        m_vertexCount++;
    }

    for (int i = 1; i < 4; i++) {
        const auto pos = m_cmdFIFO[i * 2 + 1];
        const auto texcoord = m_cmdFIFO[i * 2 + 2];

        m_vertices[m_vertexCount] = Vertex(pos, colour, clut, texpage, texcoord);
        m_vertexCount++;
    }

    renderBatch();
    glUniform1i(m_texturedLoc, 0);
}

void PCSX::OpenGL_GPU::cmdUnimplemented() { PCSX::g_system->printf("Unknown GP0 command: %02X\n", m_cmdFIFO[0] >> 24); }
