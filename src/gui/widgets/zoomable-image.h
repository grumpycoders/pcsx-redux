/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

#include "imgui.h"

namespace PCSX {
namespace Widgets {

// Common zoom/pan state and input handling for image viewers.
// Subclasses provide domain-specific rendering and default view dimensions.
class ZoomableImage {
  public:
    ZoomableImage(bool &show) : m_show(show) {}
    virtual ~ZoomableImage() = default;

    void zoom(float factor, ImVec2 centerUV);
    void resetView();
    void moveTo(ImVec2 pos);

    // Subclasses override to provide their natural dimensions
    virtual ImVec2 defaultViewSize() const = 0;

  protected:
    // Call from the draw method after setting up the image. Handles scroll zoom and drag pan.
    // dimensions: current m_cornerBR - m_cornerTL
    void handlePanZoom(const ImGuiIO &io, ImVec2 dimensions);

    float m_DPI = 1.0f;

    ImVec2 m_cornerTL = {0.0f, 0.0f};
    ImVec2 m_cornerBR = {1024.0f, 512.0f};
    ImVec2 m_resolution;
    ImVec2 m_origin;
    ImVec2 m_mousePos;
    ImVec2 m_mouseUV;
    bool m_hovered = false;

    bool m_firstShown = false;

  public:
    bool &m_show;
};

}  // namespace Widgets
}  // namespace PCSX
