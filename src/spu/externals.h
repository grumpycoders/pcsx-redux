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

#include "core/decode_xa.h"

/////////////////////////////////////////////////////////
// Generic defines
/////////////////////////////////////////////////////////

#define PSE_LT_SPU 4
#define PSE_SPU_ERR_SUCCESS 0
#define PSE_SPU_ERR -60
#define PSE_SPU_ERR_NOTCONFIGURED PSE_SPU_ERR - 1
#define PSE_SPU_ERR_INIT PSE_SPU_ERR - 2

/////////////////////////////////////////////////////////
// Temporary flags
/////////////////////////////////////////////////////////

// Used for debug channel muting.
#define FLAG_MUTE 1

// Used for simple interpolation.
#define FLAG_IPOL0 2
#define FLAG_IPOL1 4
