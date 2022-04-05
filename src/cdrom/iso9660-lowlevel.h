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

#include "support/binstruct.h"
#include "support/typestring-wrapper.h"

namespace PCSX {

namespace ISO9660LowLevel {

typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Year")> ShortDate_Year;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Month")> ShortDate_Month;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Day")> ShortDate_Day;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Hour")> ShortDate_Hour;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Minute")> ShortDate_Minute;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Second")> ShortDate_Second;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Offset")> ShortDate_Offset;
typedef BinStruct::Struct<TYPESTRING("ShortDate"), ShortDate_Year, ShortDate_Month, ShortDate_Day, ShortDate_Hour,
                          ShortDate_Minute, ShortDate_Second, ShortDate_Offset>
    ShortDate;

typedef BinStruct::Field<BinStruct::CString<4>, TYPESTRING("Year")> LongDate_Year;
typedef BinStruct::Field<BinStruct::CString<2>, TYPESTRING("Month")> LongDate_Month;
typedef BinStruct::Field<BinStruct::CString<2>, TYPESTRING("Day")> LongDate_Day;
typedef BinStruct::Field<BinStruct::CString<2>, TYPESTRING("Hour")> LongDate_Hour;
typedef BinStruct::Field<BinStruct::CString<2>, TYPESTRING("Minute")> LongDate_Minute;
typedef BinStruct::Field<BinStruct::CString<2>, TYPESTRING("Second")> LongDate_Second;
typedef BinStruct::Field<BinStruct::CString<2>, TYPESTRING("Hundredths")> LongDate_Hundredths;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("TZ")> LongDate_TZ;
typedef BinStruct::Struct<TYPESTRING("LongDate"), LongDate_Year, LongDate_Month, LongDate_Day, LongDate_Hour,
                          LongDate_Minute, LongDate_Second, LongDate_Hundredths, LongDate_TZ>
    LongDate;

typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Length")> DirEntry_Length;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("ExtLength")> DirEntry_ExtLength;
typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("LBA")> DirEntry_LBA;
typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("LBABE")> DirEntry_LBABE;
typedef BinStruct::Field<BinStruct::UInt32, TYPESTRING("Size")> DirEntry_Size;
typedef BinStruct::Field<BinStruct::BEUInt32, TYPESTRING("SizeBE")> DirEntry_SizeBE;
typedef BinStruct::StructField<ShortDate, TYPESTRING("Date")> DirEntry_Date;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Flags")> DirEntry_Flags;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("UnitSize")> DirEntry_UnitSize;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("InterleaveGap")> DirEntry_InterleaveGap;
typedef BinStruct::Field<BinStruct::UInt16, TYPESTRING("VolSeqNo")> DirEntry_VolSeqNo;
typedef BinStruct::Field<BinStruct::BEUInt16, TYPESTRING("VolSeqNoBE")> DirEntry_VolSeqNoBE;
typedef BinStruct::Field<BinStruct::NString, TYPESTRING("Filename")> DirEntry_Filename;
typedef BinStruct::Struct<TYPESTRING("DirEntry"), DirEntry_Length, DirEntry_ExtLength, DirEntry_LBA, DirEntry_LBABE,
                          DirEntry_Size, DirEntry_SizeBE, DirEntry_Date, DirEntry_Flags, DirEntry_UnitSize,
                          DirEntry_InterleaveGap, DirEntry_VolSeqNo, DirEntry_VolSeqNoBE, DirEntry_Filename>
    DirEntry;

typedef BinStruct::Field<BinStruct::BEUInt16, TYPESTRING("GroupID")> DirEntry_XA_GroupID;
typedef BinStruct::Field<BinStruct::BEUInt16, TYPESTRING("UserID")> DirEntry_XA_UserID;
typedef BinStruct::Field<BinStruct::BEUInt16, TYPESTRING("Attribs")> DirEntry_XA_Attribs;
typedef BinStruct::Field<BinStruct::CString<2>, TYPESTRING("Signature")> DirEntry_XA_Signature;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("FileNum")> DirEntry_XA_FileNum;
typedef BinStruct::Field<BinStruct::CString<5>, TYPESTRING("Reserved")> DirEntry_XA_Reserved;
typedef BinStruct::Struct<TYPESTRING("DirEntry_XA"), DirEntry_XA_GroupID, DirEntry_XA_UserID, DirEntry_XA_Attribs,
                          DirEntry_XA_Signature, DirEntry_XA_FileNum, DirEntry_XA_Reserved>
    DirEntry_XA;

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
typedef BinStruct::StructField<DirEntry, TYPESTRING("RootDir")> PVD_RootDir;
typedef BinStruct::Field<BinStruct::CString<128>, TYPESTRING("VolSetIdent")> PVD_VolSetIdent;
typedef BinStruct::Field<BinStruct::CString<128>, TYPESTRING("PublisherIdent")> PVD_PublisherIdent;
typedef BinStruct::Field<BinStruct::CString<128>, TYPESTRING("DataPreparerIdent")> PVD_DataPreparerIdent;
typedef BinStruct::Field<BinStruct::CString<128>, TYPESTRING("ApplicationIdent")> PVD_ApplicationIdent;
typedef BinStruct::Field<BinStruct::CString<37>, TYPESTRING("CopyrightFileIdent")> PVD_CopyrightFileIdent;
typedef BinStruct::Field<BinStruct::CString<37>, TYPESTRING("AbstractFileIdent")> PVD_AbstractFileIdent;
typedef BinStruct::Field<BinStruct::CString<37>, TYPESTRING("BibliographicFileIdent")> PVD_BibliographicFileIdent;
typedef BinStruct::StructField<LongDate, TYPESTRING("VolumeCreationDate")> PVD_VolumeCreationDate;
typedef BinStruct::StructField<LongDate, TYPESTRING("VolumeModificationDate")> PVD_VolumeModificationDate;
typedef BinStruct::StructField<LongDate, TYPESTRING("VolumeExpirationDate")> PVD_VolumeExpirationDate;
typedef BinStruct::StructField<LongDate, TYPESTRING("VolumeEffectiveDate")> PVD_VolumeEffectiveDate;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("FileStructureVersion")> PVD_FileStructureVersion;
typedef BinStruct::Field<BinStruct::UInt8, TYPESTRING("Unused4")> PVD_Unused4;
typedef BinStruct::Field<BinStruct::CString<512>, TYPESTRING("ApplicationUse")> PVD_ApplicationUse;
typedef BinStruct::Field<BinStruct::CString<653>, TYPESTRING("Reserved")> PVD_Reserved;
typedef BinStruct::Struct<
    TYPESTRING("PVD"), PVD_TypeCode, PVD_StdIdent, PVD_Version, PVD_Unused1, PVD_SystemIdent, PVD_VolumeIdent,
    PVD_Unused2, PVD_VolumeSpaceSize, PVD_VolumeSpaceSizeBE, PVD_Unused3, PVD_VolumeSetSize, PVD_VolumeSetSizeBE,
    PVD_VolumeSequenceNumber, PVD_VolumeSequenceNumberBE, PVD_LogicalBlockSize, PVD_LogicalBlockSizeBE,
    PVD_PathTableSize, PVD_PathTableSizeBE, PVD_LPathTableLocation, PVD_LPathTableOptLocation, PVD_MPathTableLocation,
    PVD_MPathTableOptLocation, PVD_RootDir, PVD_VolSetIdent, PVD_PublisherIdent, PVD_DataPreparerIdent,
    PVD_ApplicationIdent, PVD_CopyrightFileIdent, PVD_AbstractFileIdent, PVD_BibliographicFileIdent,
    PVD_VolumeCreationDate, PVD_VolumeModificationDate, PVD_VolumeExpirationDate, PVD_VolumeEffectiveDate,
    PVD_FileStructureVersion, PVD_Unused4, PVD_ApplicationUse, PVD_Reserved>
    PVD;

}  // namespace ISO9660LowLevel
}  // namespace PCSX
