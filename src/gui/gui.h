/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <SDL.h>

#include "imgui.h"

namespace PCSX {

class GUI final {
  public:
    void init();
    void update();
    void flip();
    void bindVRAMTexture();
    static void checkGL();

  private:
    void startFrame();
    void endFrame();

    SDL_Window *s_window = NULL;
    SDL_GLContext s_glContext = NULL;
    unsigned int s_VRAMTexture = 0;

    unsigned int s_offscreenFrameBuffer = 0;
    unsigned int s_offscreenTextures[2] = {0, 0};
    unsigned int s_offscreenDepthBuffer = 0;
    int s_currentTexture;

    ImVec4 clear_color = ImColor(114, 144, 154);
};

}
