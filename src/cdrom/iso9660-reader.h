/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <stdint.h>

#include <memory>

#include "support/binstruct.h"
#include "support/file.h"
#include "support/typestring-wrapper.h"

namespace PCSX {

class CDRiso;

class ISO9660Reader {
  public:
    ISO9660Reader(std::shared_ptr<CDRiso>);

    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Year")> ShortDate_Year;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Month")> ShortDate_Month;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Day")> ShortDate_Day;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Hour")> ShortDate_Hour;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Minute")> ShortDate_Minute;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Second")> ShortDate_Second;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Offset")> ShortDate_Offset;
    typedef BinStruct::Struct<ShortDate_Year, ShortDate_Month, ShortDate_Day, ShortDate_Hour, ShortDate_Minute,
                              ShortDate_Second, ShortDate_Offset>
        ShortDate;

    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Length")> DirEntry_Length;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("ExtLength")> DirEntry_ExtLength;
    typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("LBA")> DirEntry_LBA;
    typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("LBABE")> DirEntry_LBABE;
    typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("Size")> DirEntry_Size;
    typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("SizeBE")> DirEntry_SizeBE;

    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("TypeCode")> PVD_TypeCode;
    typedef BinStruct::Field<BinStruct::CString<5>, TYPESTRING("StdIdent")> PVD_StdIdent;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Version")> PVD_Version;
    typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Unused1")> PVD_Unused1;
    typedef BinStruct::Field<BinStruct::CString<32>, TYPESTRING("SystemIdent")> PVD_SystemIdent;
    typedef BinStruct::Field<BinStruct::CString<32>, TYPESTRING("VolumeIdent")> PVD_VolumeIdent;
    typedef BinStruct::Field<BinStruct::UInt64, TYPESTRING("Unused2")> PVD_Unused2;
    typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("VolumeSpaceSize")> PVD_VolumeSpaceSize;
    typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("VolumeSpaceSizeBE")> PVD_VolumeSpaceSizeBE;
    typedef BinStruct::Field<BinStruct::CString<32>, TYPESTRING("Unused3")> PVD_Unused3;
    typedef BinStruct::Field<BinStruct::UInt16, TYPESTRING("VolumeSetSize")> PVD_VolumeSetSize;
    typedef BinStruct::Field<BinStruct::BEUInt16, TYPESTRING("VolumeSetSizeBE")> PVD_VolumeSetSizeBE;
    typedef BinStruct::Field<BinStruct::UInt16, TYPESTRING("VolumeSequenceNumber")> PVD_VolumeSequenceNumber;
    typedef BinStruct::Field<BinStruct::BEUInt16, TYPESTRING("VolumeSequenceNumberBE")> PVD_VolumeSequenceNumberBE;
    typedef BinStruct::Field<BinStruct::UInt16, TYPESTRING("LogicalBlockSize")> PVD_LogicalBlockSize;
    typedef BinStruct::Field<BinStruct::BEUInt16, TYPESTRING("LogicalBlockSizeBE")> PVD_LogicalBlockSizeBE;
    typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("PathTableSize")> PVD_PathTableSize;
    typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("PathTableSizeBE")> PVD_PathTableSizeBE;
    typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("LPathTableLocation")> PVD_LPathTableLocation;
    typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("LPathTableOptLocation")> PVD_LPathTableOptLocation;
    typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("MPathTableLocation")> PVD_MPathTableLocation;
    typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("MPathTableOptLocation")> PVD_MPathTableOptLocation;

  private:
    std::shared_ptr<CDRiso> m_iso;
};

}  // namespace PCSX
