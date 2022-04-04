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

#include "support/zip.h"

#include "support/binstruct.h"
#include "support/typestring-wrapper.h"
#include "support/zfile.h"

typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("Signature")> Signature;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("MadeByVersion")> MadeByVersion;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("MinVersion")> MinVersion;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("GPFlag")> GPFlag;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("CompressionMethod")> CompressionMethod;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("FileTime")> FileTime;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("FileDate")> FileDate;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("CRC32")> CRC32;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("CompressedSize")> CompressedSize;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("UncompressedSize")> UncompressedSize;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("FilenameLength")> FilenameLength;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("ExtraFieldLength")> ExtraFieldLength;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("CommentLength")> CommentLength;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("DiskNumberStart")> DiskNumberStart;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt16, TYPESTRING("InternalFileAttributes")> InternalFileAttributes;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("ExternalFileAttributes")> ExternalFileAttributes;
typedef PCSX::BinStruct::Field<PCSX::BinStruct::UInt32, TYPESTRING("RelativeOffsetOfLocalHeader")>
    RelativeOffsetOfLocalHeader;
typedef PCSX::BinStruct::Struct<TYPESTRING("LocalFileHeader"), Signature, MinVersion, GPFlag, CompressionMethod,
                                FileTime, FileDate, CRC32, CompressedSize, UncompressedSize, FilenameLength,
                                ExtraFieldLength>
    LocalFileHeader;
typedef PCSX::BinStruct::Struct<TYPESTRING("CentralDirectoryFileHeader"), Signature, MadeByVersion, MinVersion, GPFlag,
                                CompressionMethod, FileTime, FileDate, CRC32, CompressedSize, UncompressedSize,
                                FilenameLength, ExtraFieldLength, CommentLength, DiskNumberStart,
                                InternalFileAttributes, ExternalFileAttributes, RelativeOffsetOfLocalHeader>
    CentralDirectoryFileHeader;

PCSX::ZipArchive::ZipArchive(IO<File> file) : m_file(file) {
    file->rSeek(0);
    while (!file->eof()) {
        uint32_t signature = file->peek<uint32_t>();
        switch (signature) {
            case 0x04034b50: {
                CompressedFile fileInfo;
                LocalFileHeader header;
                header.deserialize(file);
                auto flags = header.get<GPFlag>();
                if (flags & 8) {
                    m_failed = true;
                    return;
                }
                fileInfo.name = file->readString(header.get<FilenameLength>());
                file->skip(header.get<ExtraFieldLength>());
                fileInfo.offset = file->rTell();
                file->skip(header.get<CompressedSize>());
                fileInfo.size = header.get<UncompressedSize>();
                fileInfo.compressedSize = header.get<CompressedSize>();
                if ((fileInfo.size == 0xffffffff) && (fileInfo.compressedSize == 0xffffffff)) {
                    m_failed = true;
                    return;
                }
                auto method = header.get<CompressionMethod>();
                if ((method != 0) && (method != 8)) {
                    m_failed = true;
                    return;
                }
                fileInfo.compressed = method == 8;
                m_files.push_back(fileInfo);
                break;
            }
            case 0x02014b50: {
                CentralDirectoryFileHeader header;
                header.deserialize(file);
                file->skip(header.get<FilenameLength>());
                file->skip(header.get<ExtraFieldLength>());
                file->skip(header.get<CommentLength>());
                break;
            }
            case 0x06054b50: {
                return;
            }
            default: {
                m_failed = true;
                return;
            }
        }
    }
}

void PCSX::ZipArchive::listFiles(std::function<bool(const std::string_view&)> walker) {
    for (auto& file : m_files) {
        if (!file.isDirectory()) {
            if (!walker(file.name)) return;
        }
    }
}

void PCSX::ZipArchive::listDirectories(std::function<bool(const std::string_view&)> walker) {
    for (auto& file : m_files) {
        if (file.isDirectory()) {
            if (!walker(std::string_view(file.name.c_str(), file.name.length() - 1))) return;
        }
    }
}

PCSX::File* PCSX::ZipArchive::openFile(const std::string_view& path) {
    File* ret = nullptr;
    for (auto& file : m_files) {
        if (file.name == path) {
            SubFile* sub = new SubFile(m_file, file.offset, file.compressedSize);
            if (file.compressed) {
                ret = new ZReader(sub, file.size, ZReader::RAW);
            } else {
                ret = sub;
            }
            break;
        }
    }

    if (!ret) ret = new FailedFile();
    return ret;
}
