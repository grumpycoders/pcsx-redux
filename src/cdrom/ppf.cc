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

/*
 * PPF file format
 * ---------------
 *
 * As one of those things that grew organically, there's lots of problems and
 * misdocumentation around it. This is attempting to document the format and
 * its quirks. All values are stored in little endian.
 *
 * There is a 5-bytes header at the start of the file, as an ascii string:
 *
 * "PPF10", "PPF20", or "PPF30"
 *
 * The reader may think the number in ascii is indicative of the actual version,
 * but it's not, so relying on this string can be deceitful. The version is
 * actually encoded in binary as the next byte, starting at 0. So byte 5 will
 * be 0 for PPF version 1, and so on.
 *
 * Regardless of the format version, the next 50 bytes is an ascii string for
 * the description of the patch. What follows starting byte 56 will depend
 * on the version of the patch file.
 *
 * PPF version 2 and 3 added the ability to have a "FILE_ID.DIZ" embedded into
 * the patch file. Here is the method to locate and parse it:
 *
 * Basically, the section will begin with the ascii string `@BEGIN_FILE_ID.DIZ`
 * and end with the ascii string `@END_FILE_ID.DIZ`. The contents of the file
 * will be found between those two markers. Then, after the end marker, there is
 * the length of said file, including the two markers. PPFv2 will have a 32-bits
 * "length" for this file. PPFv3 reduces it to 16-bits only. The safest method
 * to locate this file is to seek near the end to attempt to find the end marker.
 *
 * PPFv1 is a very simple chunk system which has the following structure:
 *
 * - a 4 bytes offset
 * - a 1 byte length
 * - a variable length data block of length `length`, which is the patch data
 *
 * PPFv2 introduces a verification header:
 * - a 4 bytes length, representing a verification of the input file's length
 * - 1024 bytes, being a copy of some of the bytes of sector 16, aka the PVD.
 *    For normal BIN files, this means the 1024 bytes at position 0x9320. Note
 *    this amounts to 2352 * 16 + 32, to skip the sync bytes + headers, so this
 *    doesn't actually copy the pvd payload itself, but a fraction of it.
 *
 * The patching information will be the same as PPFv1.
 *
 * PPFv3 adds some new headers, starting with:
 * - a 1 byte "image type", which has the following meanings:
 *    0 for "BIN" file, with 2352 bytes per sector
 *    1 for PrimoDVD's GI files
 * - a 1 byte "verification", which has the following meanings:
 *    0 for "no verification"
 *    1 for "verification present"
 * - a 1 byte "undo data", which has the following meanings:
 *    0 for "no undo data present"
 *    1 for "undo data available"
 * - a 1 byte "reserved", which is currently always at 0
 *
 * If the "verification" flag is enabled, then this header will be followed
 * the same 1024 bytes of PVD extract as PPFv2, with the following caveat:
 * if the image type is set to 1, aka a DVD image, then the PVD extract
 * will come starting at byte 0x80a0 of the input image file, instead of
 * 0x9320.
 *
 * Then, the patch format will be different in storage, but similar in spirit:
 *
 * - an 8 bytes offset
 * - a 1 byte length
 * - a variable length data block of length `length`, which is the patch data
 * - if "undo data" is present, a variable length data block of length `length`,
 *    which is the original data, for undo purposes.
 *
 */

#include "cdrom/ppf.h"

#include <bitset>

#include "support/file.h"

bool PCSX::PPF::load(std::filesystem::path iso) {
    iso.replace_extension("ppf");
    IO<File> ppf(new PosixFile(iso));
    if (ppf->failed()) return false;

    // first 5 bytes == PPFx0 signature
    std::string sig = ppf->readString(5);
    bool proper = (sig == "PPF10") || (sig == "PPF20") || (sig == "PPF30");
    if (!proper) return false;

    // next byte == version
    auto version = m_version = ppf->read<uint8_t>();
    proper = (version == 0) || (version == 1) || (version == 2);
    if (!proper) return false;

    // next 50 bytes == description string
    m_description = ppf->readString(50);
    // reading / skipping over header
    bool hasUndo = false;
    switch (version) {
        case 1:
            // skipping over PPFv2 verification bytes
            ppf->skip(1024 + 4);
            break;
        case 2: {
            // image type HAS to be 0 for us
            if (ppf->read<uint8_t>() != 0) return false;
            // verification is a 0/1 boolean
            auto verificationByte = ppf->read<uint8_t>();
            if ((verificationByte != 0) && (verificationByte != 1)) {
                return false;
            }
            auto verification = verificationByte == 1;
            // undoData is a 0/1 boolean
            auto undoByte = ppf->read<uint8_t>();
            if ((undoByte != 0) && (undoByte != 1)) {
                return false;
            }
            hasUndo = undoByte == 1;
            // and then skip the next padding byte
            ppf->skip(1);

            // next up is to skip over the verification chunk if present
            if (verification) ppf->skip(1024);
        } break;
    }

    auto patchDataPosition = ppf->rTell();
    auto patchDataLen = ppf->size() - patchDataPosition;
    // probing for a file_id.diz
    if (version != 0) {
        // because of course, the "length" marker for the embedded file is variable
        unsigned idLen = version == 2 ? 2 : 4;
        constexpr std::string_view beginMarker = "@BEGIN_FILE_ID.DIZ";
        constexpr std::string_view endMarker = "@END_FILE_ID.DIZ";

        ppf->rSeek(endMarker.size() + idLen - patchDataLen, SEEK_END);
        if (ppf->readString(endMarker.size()) == endMarker) {
            uint32_t len = version == 2 ? ppf->read<uint16_t>() : ppf->read<uint32_t>();
            ppf->rSeek(len + idLen - patchDataLen, SEEK_END);
            if (ppf->readString(beginMarker.size()) == beginMarker) {
                patchDataLen -= idLen + len;
                m_fileIdDiz = ppf->readString(len - beginMarker.size() - endMarker.size());
            }
        }
    }

    // now that we've read our file_id.diz maybe, and adjusted our settings,
    // we create a subfile representing the patches, and process them.
    IO<File> patches(new SubFile(ppf, patchDataPosition, patchDataLen));

    while (!patches->eof()) {
        uint32_t pos = version == 2 ? patches->read<uint64_t>() : patches->read<uint32_t>();
        uint32_t len = patches->read<uint8_t>();
        uint8_t data[256];
        patches->read(data, len);
        if (hasUndo) patches->skip(len);

        uint32_t lba = pos / 2352;
        uint32_t offset = pos % 2352;
        IEC60908b::MSF msf(lba + 150);

        injectPatch(std::string_view(reinterpret_cast<char*>(data), len), offset, msf);
    }

    simplify();

    return true;
}

void PCSX::PPF::save(std::filesystem::path iso) {
    simplify();
    iso.replace_extension("ppf");
    IO<File> ppf(new PosixFile(iso, FileOps::READWRITE));
    ppf->writeString("PPF10");
    ppf->write<uint8_t>(0);
    m_description.resize(50);
    ppf->writeString(m_description);
    for (auto& patch : m_patches) {
        for (auto& d : patch.data) {
            uint32_t offset = d.first;
            uint32_t len = d.second.size();
            auto bytes = reinterpret_cast<const uint8_t*>(d.second.data());
            while (len != 0) {
                uint8_t subLen = std::min<uint32_t>(len, 255);
                ppf->write<uint32_t>(offset);
                ppf->write<uint8_t>(subLen);
                ppf->write(bytes, subLen);
                len -= subLen;
                bytes += subLen;
                offset += subLen;
            }
        }
    }
}

void PCSX::PPF::calculatePatch(const uint8_t* in, const uint8_t* out, IEC60908b::MSF msf) {
    uint32_t len = 0;
    uint32_t pos = 0;
    for (unsigned i = 0; i < 2352; i++) {
        if (in[i] == out[i]) {
            len++;
        } else {
            if (len != 0) {
                injectPatch({reinterpret_cast<const char*>(in), len}, pos, msf);
            }
        }
    }
}

void PCSX::PPF::injectPatch(std::string_view data, uint32_t offset, IEC60908b::MSF msf) {
    uint32_t end = offset + data.size();
    if (end > 2352) {
        auto sub = data.substr(0, 2352 - data.size());
        injectPatch(sub, offset, msf++);
        injectPatch(data.substr(sub.size()), 0, msf);
        return;
    }
    auto patch = m_patches.find(msf);

    if (patch == m_patches.end()) {
        patch = m_patches.insert(msf, new Patch());
    }

    patch->data.push_back({offset, std::string(data)});
}

void PCSX::PPF::maybePatchSector(uint8_t* sector, IEC60908b::MSF msf) const {
    auto patch = m_patches.find(msf);

    if (patch == m_patches.end()) return;

    for (auto& d : patch->data) {
        memcpy(sector + d.first, d.second.data(), d.second.size());
    }
}

void PCSX::PPF::simplify() {
    for (auto& patch : m_patches) simplify(patch);
}

void PCSX::PPF::simplify(IEC60908b::MSF msf) {
    auto patch = m_patches.find(msf);
    if (patch != m_patches.end()) simplify(*patch);
}

void PCSX::PPF::simplify(Patch& patch) {
    uint8_t sector[2352];
    std::bitset<2352> bitmap;
    for (auto& d : patch.data) {
        memcpy(sector + d.first, d.second.data(), d.second.size());
        for (int o = d.first; o < (d.first + d.second.size()); o++) {
            bitmap[o] = true;
        }
    }
    patch.data.clear();
    uint32_t len = 0;
    uint32_t pos = 0;
    for (unsigned i = 0; i < 2352; i++) {
        if (bitmap[i]) {
            len++;
        } else {
            if (len != 0) {
                char* ptr = reinterpret_cast<char*>(sector) + pos;
                patch.data.push_back({pos, std::string(ptr, len)});
            }
            pos = i + 1;
            len = 0;
        }
    }
    if (len != 0) {
        char* ptr = reinterpret_cast<char*>(sector) + pos;
        patch.data.push_back({pos, std::string(ptr, len)});
    }
}
