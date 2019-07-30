/***************************************************************************
                          draw.c  -  description
                             -------------------
    begin                : Sun Oct 28 2001
    copyright            : (C) 2001 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

//*************************************************************************//
// History of changes:
//
// 2008/05/17 - Pete
// - added "visual rumble" stuff to buffer swap func
//
// 2007/10/27 - MxC
// - added HQ2X/HQ3X MMX versions, and fixed stretching
//
// 2005/06/11 - MxC
// - added HQ2X,HQ3X,Scale3X screen filters
//
// 2004/01/31 - Pete
// - added zn stuff
//
// 2003/01/31 - stsp
// - added zn stuff
//
// 2003/12/30 - Stefan Sperling <stsp@guerila.com>
// - improved XF86VM fullscreen switching a little (refresh frequency issues).
//
// 2002/12/30 - Pete
// - added Scale2x display mode - Scale2x (C) 2002 Andrea Mazzoleni - http://scale2x.sourceforge.net
//
// 2002/12/29 - Pete
// - added gun cursor display
//
// 2002/12/21 - linuzappz
// - some more messages for DGA2 errors
// - improved XStretch funcs a little
// - fixed non-streched modes for DGA2
//
// 2002/11/10 - linuzappz
// - fixed 5bit masks for 2xSai/etc
//
// 2002/11/06 - Pete
// - added 2xSai, Super2xSaI, SuperEagle
//
// 2002/08/09 - linuzappz
// - added DrawString calls for DGA2 (FPS display)
//
// 2002/03/10 - lu
// - Initial SDL-only blitting function
// - Initial SDL stretch function (using an undocumented SDL 1.2 func)
// - Boht are triggered by -D_SDL -D_SDL2
//
// 2002/02/18 - linuzappz
// - NoStretch, PIC and Scanlines support for DGA2 (32bit modes untested)
// - Fixed PIC colors in CreatePic for 16/15 bit modes
//
// 2002/02/17 - linuzappz
// - Added DGA2 support, support only with no strecthing disabled (also no FPS display)
//
// 2002/01/13 - linuzappz
// - Added timing for the szDebugText (to 2 secs)
//
// 2002/01/05 - Pete
// - fixed linux stretch centering (no more garbled screens)
//
// 2001/12/30 - Pete
// - Added linux fullscreen desktop switching (non-SDL version, define USE_XF86VM in Makefile)
//
// 2001/12/19 - syo
// - support refresh rate change
// - added  wait VSYNC
//
// 2001/12/16 - Pete
// - Added Windows FPSE RGB24 mode switch
//
// 2001/12/05 - syo (syo68k@geocities.co.jp)
// - modified for "Use system memory" option
//   (Pete: fixed "system memory" save state pic surface)
//
// 2001/11/11 - lu
// - SDL additions
//
// 2001/10/28 - Pete
// - generic cleanup for the Peops release
//
//*************************************************************************//

#include <SDL.h>
#include <stdint.h>

#include "GL/gl3w.h"
#include "gpu/draw.h"
#include "gpu/externals.h"
#include "gpu/gpu.h"
#include "gpu/menu.h"
#include "gpu/prim.h"
#include "gui/gui.h"

////////////////////////////////////////////////////////////////////////////////////
// misc globals
////////////////////////////////////////////////////////////////////////////////////
int iFastFwd = 0;
PSXPoint_t ptCursorPoint[8];
uint16_t usCursorActive = 0;

PCSX::GUI *m_gui;
bool bVsync_Key = false;

////////////////////////////////////////////////////////////////////////

static const unsigned int pitch = 4096;

////////////////////////////////////////////////////////////////////////

void DoClearScreenBuffer(void)  // CLEAR DX BUFFER
{
    glClearColor(1, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
}

////////////////////////////////////////////////////////////////////////

void DoClearFrontBuffer(void)  // CLEAR PRIMARY BUFFER
{
    glClearColor(1, 0, 0, 0);
    glClear(GL_COLOR_BUFFER_BIT);
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

void ShowGunCursor(unsigned char *surf) {
    uint16_t dx = (uint16_t)PreviousPSXDisplay.Range.x1;
    uint16_t dy = (uint16_t)PreviousPSXDisplay.DisplayMode.y;
    int x, y, iPlayer, sx, ex, sy, ey;

    if (PreviousPSXDisplay.Range.y0)  // centering needed?
    {
        surf += PreviousPSXDisplay.Range.y0 * pitch;
        dy -= PreviousPSXDisplay.Range.y0;
    }

    const uint32_t crCursorColor32[8] = {0xffff0000, 0xff00ff00, 0xff0000ff, 0xffff00ff,
                                         0xffffff00, 0xff00ffff, 0xffffffff, 0xff7f7f7f};

    surf += PreviousPSXDisplay.Range.x0 << 2;  // -> add x left border

    for (iPlayer = 0; iPlayer < 8; iPlayer++)  // -> loop all possible players
    {
        if (usCursorActive & (1 << iPlayer))  // -> player active?
        {
            const int ty = (ptCursorPoint[iPlayer].y * dy) / 256;  // -> calculate the cursor pos in the current display
            const int tx = (ptCursorPoint[iPlayer].x * dx) / 512;
            sx = tx - 5;
            if (sx < 0) {
                if (sx & 1)
                    sx = 1;
                else
                    sx = 0;
            }
            sy = ty - 5;
            if (sy < 0) {
                if (sy & 1)
                    sy = 1;
                else
                    sy = 0;
            }
            ex = tx + 6;
            if (ex > dx) ex = dx;
            ey = ty + 6;
            if (ey > dy) ey = dy;

            for (x = tx, y = sy; y < ey; y += 2)  // -> do dotted y line
                *((uint32_t *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
            for (y = ty, x = sx; x < ex; x += 2)  // -> do dotted x line
                *((uint32_t *)((surf) + (y * pitch) + x * 4)) = crCursorColor32[iPlayer];
        }
    }
}

static void checkGL() {
    volatile GLenum error = glGetError();
    if (error != GL_NO_ERROR) {
        SDL_TriggerBreakpoint();
        abort();
    }
}

static const GLchar *passThroughVS = GL_SHADER_VERSION R"(
in vec2 in_Position;
in vec2 in_Texcoord;

out highp vec2 v_texcoord;
void main(void) {
  gl_Position = vec4(in_Position.x, in_Position.y, 0.0, 1.0);
  v_texcoord = in_Texcoord;
}
)";

static const GLchar *PS_16 = GL_SHADER_VERSION R"(
precision highp float;
in highp vec2 v_texcoord;

out vec4 FragColor;

uniform sampler2D s_texture;

void main(void) {
    FragColor = texture(s_texture, v_texcoord);
    FragColor.a = 1.f;
}
)";

static const GLchar *PS_24 = GL_SHADER_VERSION R"(
precision highp float;
in highp vec2 v_texcoord;

out vec4 FragColor;

uniform sampler2D s_texture;

void main(void) {
    FragColor = texture(s_texture, v_texcoord);
    FragColor.a = 1.f;
}
)";

static GLuint compileShader(const char *VS, const char *PS) {
    GLuint vertexshader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(vertexshader, 1, &VS, 0);
    glCompileShader(vertexshader);
    GLint IsCompiled_VS = 0;
    glGetShaderiv(vertexshader, GL_COMPILE_STATUS, &IsCompiled_VS);
    if (IsCompiled_VS == 0) {
        GLint maxLength;
        glGetShaderiv(vertexshader, GL_INFO_LOG_LENGTH, &maxLength);
        char *vertexInfoLog = (char *)malloc(maxLength);

        glGetShaderInfoLog(vertexshader, maxLength, &maxLength, vertexInfoLog);

        SDL_TriggerBreakpoint();
        assert(false);

        free(vertexInfoLog);
    }

    GLuint fragmentshader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(fragmentshader, 1, &PS, 0);
    glCompileShader(fragmentshader);
    GLint IsCompiled_PS = 0;
    glGetShaderiv(fragmentshader, GL_COMPILE_STATUS, &IsCompiled_PS);
    if (IsCompiled_PS == 0) {
        GLint maxLength;
        glGetShaderiv(fragmentshader, GL_INFO_LOG_LENGTH, &maxLength);
        char *fragmentInfoLog = (char *)malloc(maxLength);

        glGetShaderInfoLog(fragmentshader, maxLength, &maxLength, fragmentInfoLog);

        SDL_TriggerBreakpoint();
        assert(false);

        free(fragmentInfoLog);
    }

    GLuint shaderprogram = glCreateProgram();
    glAttachShader(shaderprogram, vertexshader);
    glAttachShader(shaderprogram, fragmentshader);

    glLinkProgram(shaderprogram);

    GLint IsLinked = 0;
    glGetProgramiv(shaderprogram, GL_LINK_STATUS, &IsLinked);
    assert(IsLinked);

    return shaderprogram;
}

struct s_vertexData {
    float positions[3];
    float textures[2];
};

static GLuint vao_handle = 0;
static GLuint shaderprogram16 = 0;
static GLuint shaderprogram24 = 0;
static GLuint vertexp = 0;
static GLuint texcoordp = 0;
static GLuint vbo = 0;
static GLuint vramTexture = 0;

static void DrawFullscreenQuad(int is24Bit) {
    glBindVertexArray(vao_handle);

    if (is24Bit) {
        glUseProgram(shaderprogram24);
    } else {
        glUseProgram(shaderprogram16);
    }

    float xRatio = 1 / 1024.f;
    if (is24Bit) {
        xRatio = (1 / 1.5f) * (1.f / 1024.f);
    }

    float startX = PSXDisplay.DisplayPosition.x * xRatio;
    float width = (PSXDisplay.DisplayEnd.x - PSXDisplay.DisplayPosition.x) / 1024.f;

    s_vertexData quadVertices[6];

    quadVertices[0].positions[0] = -1;
    quadVertices[0].positions[1] = -1;
    quadVertices[0].positions[2] = 0;
    quadVertices[0].textures[0] = startX;
    quadVertices[0].textures[1] = PSXDisplay.DisplayPosition.y / 512.f;

    quadVertices[1].positions[0] = 1;
    quadVertices[1].positions[1] = -1;
    quadVertices[1].positions[2] = 0;
    quadVertices[1].textures[0] = startX + width;
    quadVertices[1].textures[1] = PSXDisplay.DisplayPosition.y / 512.f;

    quadVertices[2].positions[0] = 1;
    quadVertices[2].positions[1] = 1;
    quadVertices[2].positions[2] = 0;
    quadVertices[2].textures[0] = startX + width;
    quadVertices[2].textures[1] = PSXDisplay.DisplayEnd.y / 512.f;

    quadVertices[3].positions[0] = -1;
    quadVertices[3].positions[1] = -1;
    quadVertices[3].positions[2] = 0;
    quadVertices[3].textures[0] = startX;
    quadVertices[3].textures[1] = PSXDisplay.DisplayPosition.y / 512.f;

    quadVertices[4].positions[0] = -1;
    quadVertices[4].positions[1] = 1;
    quadVertices[4].positions[2] = 0;
    quadVertices[4].textures[0] = startX;
    quadVertices[4].textures[1] = PSXDisplay.DisplayEnd.y / 512.f;

    quadVertices[5].positions[0] = 1;
    quadVertices[5].positions[1] = 1;
    quadVertices[5].positions[2] = 0;
    quadVertices[5].textures[0] = startX + width;
    quadVertices[5].textures[1] = PSXDisplay.DisplayEnd.y / 512.f;

    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    checkGL();
    glBufferData(GL_ARRAY_BUFFER, sizeof(s_vertexData) * 6, &quadVertices[0], GL_STATIC_DRAW);
    checkGL();

    glDisable(GL_CULL_FACE);
    checkGL();
    glDisable(GL_DEPTH_TEST);
    checkGL();

    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    checkGL();
    glVertexAttribPointer(vertexp, 3, GL_FLOAT, GL_FALSE, sizeof(s_vertexData),
                          (void *)&((s_vertexData *)NULL)->positions);
    checkGL();
    glEnableVertexAttribArray(vertexp);
    checkGL();

    if (texcoordp != -1) {
        glVertexAttribPointer(texcoordp, 2, GL_FLOAT, GL_FALSE, sizeof(s_vertexData),
                              (void *)&((s_vertexData *)NULL)->textures);
        glEnableVertexAttribArray(texcoordp);
    }

    glDrawArrays(GL_TRIANGLES, 0, 6);
    checkGL();

    // cleanup!
    glUseProgram(0);
    glBindVertexArray(0);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}

void DoBufferSwap() {
#ifndef DO_CRASH
    m_gui->setViewport();
    m_gui->bindVRAMTexture();
//    glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 1024, 512, GL_RGBA, GL_UNSIGNED_SHORT_1_5_5_5_REV, psxVuw);
    checkGL();

    if (PSXDisplay.RGB24) {
        glBindTexture(GL_TEXTURE_2D, vramTexture);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
//        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, 682, 512, GL_RGB, GL_UNSIGNED_BYTE, psxVuw);
        checkGL();

        DrawFullscreenQuad(PSXDisplay.RGB24);
    } else {
        m_gui->bindVRAMTexture();
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
        DrawFullscreenQuad(PSXDisplay.RGB24);
    }

    glBindTexture(GL_TEXTURE_2D, 0);
    checkGL();
#endif
    m_gui->flip();
}

////////////////////////////////////////////////////////////////////////
// MAIN DIRECT DRAW INIT
////////////////////////////////////////////////////////////////////////

int DXinitialize() {
    //    InitMenu();  // menu init

    return 0;
}

////////////////////////////////////////////////////////////////////////
// clean up DX stuff
////////////////////////////////////////////////////////////////////////

void DXcleanup()  // DX CLEANUP
{
    //    CloseMenu();  // bye display lists
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

uint32_t ulInitDisplay(void) {
    DXinitialize();  // init direct draw (not D3D... oh, well)
    glGenTextures(1, &vramTexture);
    checkGL();
    glBindTexture(GL_TEXTURE_2D, vramTexture);
    checkGL();
    glTexStorage2D(GL_TEXTURE_2D, 1, GL_RGB8, 1024, 512);
    checkGL();
    glGenVertexArrays(1, &vao_handle);
    checkGL();
    shaderprogram16 = compileShader(passThroughVS, PS_16);
    vertexp = glGetAttribLocation(shaderprogram16, (const GLchar *)"in_Position");
    texcoordp = glGetAttribLocation(shaderprogram16, (const GLchar *)"in_Texcoord");
    checkGL();
    shaderprogram24 = compileShader(passThroughVS, PS_24);
    assert(vertexp == glGetAttribLocation(shaderprogram24, (const GLchar *)"in_Position"));
    assert(texcoordp == glGetAttribLocation(shaderprogram24, (const GLchar *)"in_Texcoord"));
    checkGL();
    glGenBuffers(1, &vbo);
    checkGL();
    return 1;
}

////////////////////////////////////////////////////////////////////////

void CloseDisplay(void) {
    DXcleanup();  // cleanup dx
}

////////////////////////////////////////////////////////////////////////

void CreatePic(unsigned char *pMem) {}

///////////////////////////////////////////////////////////////////////////////////////

void DestroyPic(void) {}

///////////////////////////////////////////////////////////////////////////////////////

void DisplayPic(void) {}

///////////////////////////////////////////////////////////////////////////////////////

void ShowGpuPic(void) {}

////////////////////////////////////////////////////////////////////////

void ShowTextGpuPic(void)  // CREATE TEXT SCREEN PIC
{                          // gets an Text and paints
}

////////////////////////////////////////////////////////////////////////
