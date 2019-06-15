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

class SaveStates {
  public:
    typedef Protobuf::Field<Protobuf::FieldTypeString, TYPESTRING("version_string"), 1> VersionString;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("version"), 2> Version;

    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("width"), 1> Width;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("height"), 2> Height;
    typedef Protobuf::Field<Protobuf::FieldTypeBytes, TYPESTRING("red"), 3> Red;
    typedef Protobuf::Field<Protobuf::FieldTypeBytes, TYPESTRING("green"), 4> Green;
    typedef Protobuf::Field<Protobuf::FieldTypeBytes, TYPESTRING("blue"), 5> Blue;
    typedef Protobuf::Message<TYPESTRING("Thumbnail"), Width, Height, Red, Green, Blue> Thumbnail;
    typedef Protobuf::MessageField<Thumbnail, TYPESTRING("thumbnail"), 3> ThumbnailField;

    typedef Protobuf::Field<Protobuf::FieldTypeBytes, TYPESTRING("ram"), 1> RAM;
    typedef Protobuf::Field<Protobuf::FieldTypeBytes, TYPESTRING("rom"), 2> ROM;
    typedef Protobuf::Field<Protobuf::FieldTypeBytes, TYPESTRING("parallel"), 3> Parallel;
    typedef Protobuf::Field<Protobuf::FieldTypeBytes, TYPESTRING("scratchpad"), 4> ScratchPad;
    typedef Protobuf::Message<TYPESTRING("Memory"), RAM, ROM, Parallel, ScratchPad> Memory;
    typedef Protobuf::MessageField<Memory, TYPESTRING("memory"), 4> MemoryField;

    typedef Protobuf::RepeatedField<Protobuf::FieldTypeUInt32, TYPESTRING("gpr"), 1> GPR;
    typedef Protobuf::RepeatedField<Protobuf::FieldTypeUInt32, TYPESTRING("cp0"), 2> CP0;
    typedef Protobuf::RepeatedField<Protobuf::FieldTypeUInt32, TYPESTRING("cp2d"), 3> CP2D;
    typedef Protobuf::RepeatedField<Protobuf::FieldTypeUInt32, TYPESTRING("cp2c"), 4> CP2C;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("pc"), 5> PC;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("code"), 6> Code;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("cycle"), 7> Cycle;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("interrupt"), 8> Interrupt;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("scycle"), 1> IntSCycle;
    typedef Protobuf::Field<Protobuf::FieldTypeUInt32, TYPESTRING("cycle"), 2> IntCycle;
    typedef Protobuf::Message<TYPESTRING("InterruptCycles"), IntSCycle, IntCycle> IntCycles;
    typedef Protobuf::MessageField<IntCycles, TYPESTRING("interrupt_cycles"), 9> IntCyclesField;
    typedef Protobuf::Message<TYPESTRING("Registers"), GPR, CP0, CP2D, CP2C, PC, Code, Cycle, IntCyclesField> Registers;
    typedef Protobuf::MessageField<Registers, TYPESTRING("registers"), 5> RegistersField;

    typedef Protobuf::Message<TYPESTRING("SaveState"), VersionString, Version, ThumbnailField, MemoryField, RegistersField> SaveState;
};

}  // namespace PCSX
