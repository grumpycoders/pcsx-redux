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

#include "hwregs.h"

#define SPU_MVOL_L HW_U16(0x1f801d80)
#define SPU_MVOL_R HW_U16(0x1f801d82)
#define SPU_REVERB_L HW_U16(0x1f801d84)
#define SPU_REVERB_R HW_U16(0x1f801d86)

static __inline__ void muteSpu() {
    SPU_REVERB_R = 0;
    SPU_REVERB_L = 0;
    SPU_MVOL_R = 0;
    SPU_MVOL_L = 0;
}
