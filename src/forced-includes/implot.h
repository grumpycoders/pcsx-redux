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

#include "../forced-includes/imgui.h"

// ImPlot's IM_ASSERT_USER_ERROR sites do not return after asserting, so the
// GUI's record-and-continue user error handler would let ImPlot go on to
// dereference invalid state. Always throw for ImPlot instead.
#undef IM_ASSERT_USER_ERROR
#define IM_ASSERT_USER_ERROR(EXP, MSG) pcsxStaticImguiAssert(!!(EXP), (MSG))
