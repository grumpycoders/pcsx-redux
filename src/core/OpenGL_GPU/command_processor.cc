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

    m_cmdFuncs[0x2C] = &OpenGL_GPU::drawPoly<PolyType::Quad, Shading::Flat, Texturing::Textured>;  // TODO: Blending
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
void PCSX::OpenGL_GPU::cmdClearTexCache() {}

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

    m_drawingOffset.x() = static_cast<float>(offsetX);
    m_drawingOffset.y() = static_cast<float>(offsetY);

    // The 0.5 offsets help fix some holes in rendering, in places like the PS logo
    // TODO: This might not work when upscaling?
    float adjustedOffsets[2] = {m_drawingOffset.x() + 0.5f, m_drawingOffset.y() - 0.5f};
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
    const uint32_t width = res & 0xffff;
    const uint32_t height = res >> 16;
    if (width == 0 || height == 0) PCSX::g_system->printf("Weird %dx%d texture transfer\n", width, height);

    // TODO: Sanitize this
    m_vramTransferRect.x = coords & 0xffff;
    m_vramTransferRect.y = coords >> 16;
    m_vramTransferRect.width = width;
    m_vramTransferRect.height = height;

    // The size of the texture in 16-bit pixels. If the number is odd, force align it up
    const uint32_t size = ((width * height) + 1) & ~1;
    m_remainingWords = size / 2;
}

void PCSX::OpenGL_GPU::cmdCopyRectFromVRAM() { PCSX::g_system->printf("Attempted to read back VRAM :(\n"); }

void PCSX::OpenGL_GPU::cmdUnimplemented() { PCSX::g_system->printf("Unknown GP0 command: %02X\n", m_cmdFIFO[0] >> 24); }