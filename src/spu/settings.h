/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include "support/settings.h"

namespace PCSX {
namespace SPU {

typedef SettingString<TYPESTRING("Backend"), TYPESTRING("Default")> Backend;
typedef SettingString<TYPESTRING("Device"), TYPESTRING("Default")> Device;
typedef Setting<bool, TYPESTRING("Streaming"), true> Streaming;
typedef Setting<int, TYPESTRING("Volume"), 3> Volume;
typedef Setting<bool, TYPESTRING("IRQWait"), true> SPUIRQWait;
typedef Setting<int, TYPESTRING("Reverb"), 2> Reverb;
typedef Setting<int, TYPESTRING("Interp"), 2> Interpolation;
typedef Setting<bool, TYPESTRING("Mono")> Mono;
typedef Setting<bool, TYPESTRING("DBufIRQ")> DBufIRQ;
typedef Setting<bool, TYPESTRING("Mute")> Mute;
typedef Settings<Backend, Device, Streaming, Volume, SPUIRQWait, Reverb, Interpolation, Mono, DBufIRQ, Mute>
    SettingsType;

}  // namespace SPU
}  // namespace PCSX
