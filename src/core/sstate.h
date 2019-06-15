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

#include "core/protobuf.h"
#include "main/settings.h"

namespace PCSX {

namespace SaveStates {
typedef Protobuf::Field<Protobuf::String, TYPESTRING("version_string"), 1> VersionString;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("version"), 2> Version;

typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("width"), 1> Width;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("height"), 2> Height;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("red"), 3> Red;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("green"), 4> Green;
typedef Protobuf::Field<Protobuf::Bytes, TYPESTRING("blue"), 5> Blue;
typedef Protobuf::Message<TYPESTRING("Thumbnail"), Width, Height, Red, Green, Blue> Thumbnail;
typedef Protobuf::MessageField<Thumbnail, TYPESTRING("thumbnail"), 3> ThumbnailField;

typedef Protobuf::FieldRef<Protobuf::FixedBytes<0x00200000>, TYPESTRING("ram"), 1> RAM;
typedef Protobuf::FieldRef<Protobuf::FixedBytes<0x00080000>, TYPESTRING("rom"), 2> ROM;
typedef Protobuf::FieldRef<Protobuf::FixedBytes<0x00010000>, TYPESTRING("parallel"), 3> Parallel;
typedef Protobuf::FieldRef<Protobuf::FixedBytes<0x00010000>, TYPESTRING("hardware"), 4> Hardware;
typedef Protobuf::Message<TYPESTRING("Memory"), RAM, ROM, Parallel, Hardware> Memory;
typedef Protobuf::MessageField<Memory, TYPESTRING("memory"), 4> MemoryField;

typedef Protobuf::RepeatedFieldRef<34, Protobuf::UInt32, TYPESTRING("gpr"), 1> GPR;
typedef Protobuf::RepeatedFieldRef<32, Protobuf::UInt32, TYPESTRING("cp0"), 2> CP0;
typedef Protobuf::RepeatedFieldRef<32, Protobuf::UInt32, TYPESTRING("cp2d"), 3> CP2D;
typedef Protobuf::RepeatedFieldRef<32, Protobuf::UInt32, TYPESTRING("cp2c"), 4> CP2C;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("pc"), 5> PC;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("code"), 6> Code;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("cycle"), 7> Cycle;
typedef Protobuf::FieldRef<Protobuf::UInt32, TYPESTRING("interrupt"), 8> Interrupt;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("scycle"), 1> IntSCycle;
typedef Protobuf::Field<Protobuf::UInt32, TYPESTRING("cycle"), 2> IntCycle;
typedef Protobuf::Message<TYPESTRING("InterruptCycles"), IntSCycle, IntCycle> IntCycles;
typedef Protobuf::MessageField<IntCycles, TYPESTRING("interrupt_cycles"), 9> IntCyclesField;
typedef Protobuf::Message<TYPESTRING("Registers"), GPR, CP0, CP2D, CP2C, PC, Code, Cycle, Interrupt, IntCyclesField> Registers;
typedef Protobuf::MessageField<Registers, TYPESTRING("registers"), 5> RegistersField;

typedef Protobuf::Message<TYPESTRING("SaveState"), VersionString, Version, ThumbnailField, MemoryField, RegistersField>
    SaveState;

typedef Protobuf::ProtoFile<Thumbnail, Memory, IntCycles, Registers, SaveState> ProtoFile;

std::string save();
}  // namespace SaveStates

}  // namespace PCSX
