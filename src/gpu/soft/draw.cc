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

#include <cstdint>

#include "GL/gl3w.h"
#include "gpu/soft/interface.h"
#include "gpu/soft/soft.h"
#include "gui/gui.h"

// The VRAM resolve pass. m_vramTexture16 holds raw 16-bit PS1 words in a
// GL_R16UI integer texture, which nothing downstream is equipped to sample:
// the offscreen shader editor is handed a GL_RGB texture in 24bpp mode and a
// GL_RGBA8 one by the hardware backend, so its sampler cannot be usampler2D,
// and it is user-editable besides. This pass unpacks 1555 into a plain
// GL_RGBA8 texture once, and everything downstream keeps seeing what it always
// saw. Same shape as the 16-to-24 pass in the OpenGL backend.
//
// Doing the unpack here rather than in a packed texture format is also what
// makes linear filtering correct: interpolating the raw words would blend
// bit-fields against each other. The filter now applies to this output.
static const GLchar *const c_resolveVertexShader = GL_SHADER_VERSION R"(
// Fullscreen triangle from gl_VertexID; no vertex buffer needed.
void main() {
    vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
    gl_Position = vec4(p * 2.0f - 1.0f, 0.0f, 1.0f);
}
)";

static const GLchar *const c_resolvePixelShader = GL_SHADER_VERSION R"(
precision highp float;
precision highp usampler2D;
uniform usampler2D u_vram;
layout (location = 0) out vec4 Out_Color;
void main() {
    // PS1 VRAM word: bit 15 is the mask bit, 14-10 blue, 9-5 green, 4-0 red.
    // That is exactly what GL_UNSIGNED_SHORT_1_5_5_5_REV used to decode for us
    // on desktop, and what GLES3 has no packed format for at all.
    // Alpha carries bit 15 rather than a constant 1.0: that is precisely what
    // the old packed decode produced, and the VRAM viewer reads it back out of
    // this channel to reconstruct the raw word. Flattening it to 1.0 would look
    // identical on the display and silently break the viewer's mask-bit column.
    uint w = texelFetch(u_vram, ivec2(gl_FragCoord.xy), 0).r;
    Out_Color = vec4(float(w & 31u) / 31.0f,
                     float((w >> 5) & 31u) / 31.0f,
                     float((w >> 10) & 31u) / 31.0f,
                     float((w >> 15) & 1u));
}
)";

void PCSX::SoftGPU::impl::resolveVRAM() {
    GLint oldFBO = 0, oldViewport[4];
    glGetIntegerv(GL_FRAMEBUFFER_BINDING, &oldFBO);
    glGetIntegerv(GL_VIEWPORT, oldViewport);
    const auto oldBlend = OpenGL::isEnabled(GL_BLEND);
    const auto oldScissor = OpenGL::scissorEnabled();

    m_resolveFBO.bind(OpenGL::DrawAndReadFramebuffer);
    glViewport(0, 0, 1024, 512);
    glDisable(GL_BLEND);
    glDisable(GL_SCISSOR_TEST);
    glUseProgram(m_resolveProgram.handle());
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glUniform1i(m_resolveTexLoc, 0);
    m_resolveVAO.bind();
    glDrawArrays(GL_TRIANGLES, 0, 3);

    glBindFramebuffer(GL_FRAMEBUFFER, oldFBO);
    glViewport(oldViewport[0], oldViewport[1], oldViewport[2], oldViewport[3]);
    if (oldBlend) OpenGL::enableBlend();
    if (oldScissor) OpenGL::enableScissor();
}

void PCSX::SoftGPU::impl::doBufferSwap(bool fromGui) {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) {
        return;
    }
    gui->setViewport();
    GLuint textureID;

    if (m_softDisplay.RGB24) {
        auto offset = (m_softDisplay.DisplayPosition.x * 2) % 3;
        textureID = m_vramTexture24;
        glBindTexture(GL_TEXTURE_2D, textureID);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 682, 512, GL_RGB, GL_UNSIGNED_BYTE, m_vram + offset);
    } else {
        glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RED_INTEGER, GL_UNSIGNED_SHORT, m_vram16);
        // What leaves here is RGBA8, not the raw words, so every downstream
        // consumer - the user's offscreen shader, CRT-Lottes, the 24bpp path
        // above - is unchanged by the storage format underneath.
        resolveVRAM();
        textureID = m_vramTextureResolved.handle();
    }

    float xRatio = m_softDisplay.RGB24 ? ((1.0f / 1.5f) * (1.0f / 1024.0f)) : (1.0f / 1024.0f);

    float startX = m_softDisplay.DisplayPosition.x * xRatio;
    float startY = m_softDisplay.DisplayPosition.y / 512.0f;
    float width = (m_softDisplay.DisplayEnd.x - m_softDisplay.DisplayPosition.x) / 1024.0f;
    float height = (m_softDisplay.DisplayEnd.y - m_softDisplay.DisplayPosition.y) / 512.0f;

    // Temporary workaround until we make our Display struct work with the sw backend
    // Trim 1 pixel from the height and width when linear filtering is on to avoid artifacts due to wrong sampling
    if (g_emulator->settings.get<Emulator::SettingLinearFiltering>()) {
        width -= 1.f / 1024.f;
        height -= 1.f / 512.f;
    }

    gui->m_offscreenShaderEditor.render(gui, textureID, {startX, startY}, {width, height}, gui->getRenderSize());
    if (!fromGui) gui->flip();
}

void PCSX::SoftGPU::impl::clearVRAM() {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) return;
    const auto oldTex = OpenGL::getTex2D();
    std::memset(m_allocatedVRAM, 0x00, (VRAM_HEIGHT * 2) * 1024 + (1024 * 1024));

    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RED_INTEGER, GL_UNSIGNED_SHORT, m_allocatedVRAM);
    glBindTexture(GL_TEXTURE_2D, oldTex);
}

void PCSX::SoftGPU::impl::setLinearFiltering() {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) return;
    const auto filter = g_emulator->settings.get<Emulator::SettingLinearFiltering>().value ? GL_LINEAR : GL_NEAREST;
    glBindTexture(GL_TEXTURE_2D, m_vramTexture24);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);

    // The 16bpp path's filter belongs on the RESOLVED texture: this is the one
    // the offscreen shader actually samples, and it holds unpacked colour, so
    // interpolating it means what the user asked for. The old code filtered the
    // packed 1555 texture, which blended bit-fields.
    m_vramTextureResolved.bind();
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, filter);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, filter);

    // m_vramTexture16 deliberately stays GL_NEAREST whatever the setting says.
    // It is a GL_R16UI integer texture now, and filtering an integer format is
    // not merely wrong output, it is invalid. The setting is still honoured for
    // the 16bpp path - the offscreen shader does the interpolation, which is
    // the correct place for it anyway: bilinear on packed 1555 words blends
    // bit patterns rather than colours, so the old driver-side filtering was
    // producing garbage in the low bits of each channel.
    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
}

void PCSX::SoftGPU::impl::initDisplay() {
    GUI *gui = dynamic_cast<GUI *>(m_ui);
    if (!gui) return;
    glGenTextures(1, &m_vramTexture24);
    glBindTexture(GL_TEXTURE_2D, m_vramTexture24);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, 1024, 512, 0, GL_RGB, GL_UNSIGNED_BYTE, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    glGenTextures(1, &m_vramTexture16);
    glBindTexture(GL_TEXTURE_2D, m_vramTexture16);
    // Raw 16-bit VRAM words, as an integer texture rather than a packed colour
    // format. GL_UNSIGNED_SHORT_1_5_5_5_REV does not exist in GLES3/WebGL2 at
    // all, and its GLES cousin GL_UNSIGNED_SHORT_5_5_5_1 is not a substitute -
    // _REV puts red in the low bits, matching the PS1's X1B5G5R5 word, while
    // 5_5_5_1 puts it in the high bits. Handing the shader the untouched word
    // and unpacking there is exact on every platform and needs no swizzle.
    glTexImage2D(GL_TEXTURE_2D, 0, GL_R16UI, 1024, 512, 0, GL_RED_INTEGER, GL_UNSIGNED_SHORT, nullptr);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);

    // The resolve target. RGBA8 because that is what every downstream consumer
    // is built to sample, and 1024x512 so that every UV the display code
    // computes against VRAM dimensions stays valid without a single change.
    m_vramTextureResolved.create(1024, 512, GL_RGBA8);
    m_vramTextureResolved.bind();
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    m_resolveFBO.createWithTexture(m_vramTextureResolved);

    // An empty VAO is still mandatory: a core profile rejects a draw call with
    // no vertex array bound, even when the vertex shader reads nothing but
    // gl_VertexID.
    m_resolveVAO.create();

    OpenGL::Shader vert, frag;
    auto status = vert.create(c_resolveVertexShader, GL_VERTEX_SHADER);
    if (status.isOk()) status = frag.create(c_resolvePixelShader, GL_FRAGMENT_SHADER);
    if (status.isOk()) status = m_resolveProgram.create({vert, frag});
    if (!status.isOk()) {
        // There is no sane fallback: without this pass the 16bpp display is a
        // raw integer texture that nothing downstream can read. Say so loudly
        // rather than render garbage and let someone hunt it later.
        g_system->printf("Failed to build the VRAM resolve shader: %s\n", status.getError().c_str());
    }
    m_resolveTexLoc = glGetUniformLocation(m_resolveProgram.handle(), "u_vram");
}
