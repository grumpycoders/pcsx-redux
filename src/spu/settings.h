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
typedef Setting<bool, TYPESTRING("UseNullSync"), false> NullSync;
typedef Setting<bool, TYPESTRING("Streaming"), true> Streaming;
typedef Setting<int, TYPESTRING("Volume"), 3> Volume;
typedef Setting<bool, TYPESTRING("IRQWait"), true> SPUIRQWait;
typedef Setting<int, TYPESTRING("Interp"), 2> Interpolation;
typedef Setting<bool, TYPESTRING("Mono")> Mono;
typedef Setting<bool, TYPESTRING("DBufIRQ"), true> DBufIRQ;
typedef Setting<bool, TYPESTRING("Mute")> Mute;
// Emulation speed multiplier, applied at the audio sink (the emulator's master clock). 1 = realtime
// (1:1 emulated:hardware), N = N times faster, <= 0 = unbounded (drain as fast as the producer fills).
// The sink decimates whole frame-runs (skip, not resample) so pitch is preserved at any multiplier.
// This replaces the old cycle-derived Emulator::SettingScaler: because both audio sources (SPU voices
// and CD-ROM XA) converge at the sink, speeding up here also speeds up XA, which the cycle scaler missed.
typedef Setting<int, TYPESTRING("Speed"), 1> Speed;
// Voice key-on -> first-output startup latency, in 44.1kHz samples. Real hardware emits a few samples of
// silence after KEY_ON before the voice's first decoded sample appears in the capture mirror; Redux emits
// immediately. EXPERIMENTAL/diagnostic default 0 (no change); set via Lua to characterize/model the offset.
typedef Setting<int, TYPESTRING("KeyOnDelay"), 0> KeyOnDelay;
typedef Settings<Backend, Device, NullSync, Streaming, Volume, SPUIRQWait, Interpolation, Mono, DBufIRQ, Mute,
                 Speed, KeyOnDelay>
    SettingsType;

}  // namespace SPU
}  // namespace PCSX
