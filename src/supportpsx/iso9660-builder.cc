/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include "supportpsx/iso9660-builder.h"

#include <stdexcept>

#include "iec-60908b/edcecc.h"

void PCSX::ISO9660Builder::writeLicense(IO<File> licenseFile) {
    if (licenseFile && !licenseFile->failed()) {
        uint8_t licenseData[IEC60908b::FRAMESIZE_RAW * 16];
        memset(licenseData, 0, sizeof(licenseData));
        licenseFile->read(licenseData, sizeof(licenseData));
        if (licenseData[0x2492] == 'L') {
            // official license file from the sdk, in 2336 bytes per sector.
            // It's unfortunately usually mangled badly, and we need to massage it.
            for (unsigned i = 0; i < 16; i++) {
                writeSectorAt(licenseData + 2336 * i + 8, {0, 2, uint8_t(i)}, IEC60908b::SectorMode::M2_FORM1);
            }
            return;
        } else if (licenseData[0x24e2] == 'L') {
            // looks like an iso file itself
            for (unsigned i = 0; i < 16; i++) {
                writeSectorAt(licenseData + IEC60908b::FRAMESIZE_RAW * i, {0, 2, uint8_t(i)},
                              IEC60908b::SectorMode::RAW);
            }
            return;
        }
    }
    uint8_t dummy[2048];
    memset(dummy, 0, 2048);
    for (unsigned i = 0; i < 16; i++) {
        writeSectorAt(dummy, {0, 2, uint8_t(i)}, IEC60908b::SectorMode::M2_FORM1);
    }
}

PCSX::IEC60908b::MSF PCSX::ISO9660Builder::writeSectorAt(const uint8_t* sectorData, PCSX::IEC60908b::MSF msf,
                                                         IEC60908b::SectorMode mode) {
    if (failed()) return {0, 0, 0};
    Slice slice;
    uint8_t* ptr;
    static const uint8_t c_sync[12] = {0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00};
    uint32_t lba = msf.toLBA() - 150;
    switch (mode) {
        case IEC60908b::SectorMode::RAW:
            m_out->writeAt(sectorData, IEC60908b::FRAMESIZE_RAW, lba * IEC60908b::FRAMESIZE_RAW);
            break;
        case IEC60908b::SectorMode::M2_RAW:
            slice.resize(IEC60908b::FRAMESIZE_RAW);
            ptr = slice.mutableData<uint8_t>();
            memcpy(ptr, c_sync, sizeof(c_sync));
            msf.toBCD(ptr + 12);
            ptr[15] = 2;
            memcpy(ptr + 16, sectorData, 2336);
            compute_edcecc(ptr);
            m_out->writeAt(std::move(slice), lba * IEC60908b::FRAMESIZE_RAW);
            break;
        case IEC60908b::SectorMode::M2_FORM1:
            slice.resize(IEC60908b::FRAMESIZE_RAW);
            ptr = slice.mutableData<uint8_t>();
            memcpy(ptr, c_sync, sizeof(c_sync));
            msf.toBCD(ptr + 12);
            ptr[15] = 2;
            ptr[16] = ptr[20] = 0;
            ptr[17] = ptr[21] = 0;
            ptr[18] = ptr[22] = 8;
            ptr[19] = ptr[23] = 0;
            memcpy(ptr + 24, sectorData, 2048);
            compute_edcecc(ptr);
            m_out->writeAt(std::move(slice), lba * IEC60908b::FRAMESIZE_RAW);
            break;
        case IEC60908b::SectorMode::M2_FORM2:
            slice.resize(IEC60908b::FRAMESIZE_RAW);
            ptr = slice.mutableData<uint8_t>();
            memcpy(ptr, c_sync, sizeof(c_sync));
            msf.toBCD(ptr + 12);
            ptr[15] = 2;
            ptr[16] = ptr[20] = 0;
            ptr[17] = ptr[21] = 0;
            ptr[18] = ptr[22] = 8;
            ptr[19] = ptr[23] = 0;
            memcpy(ptr + 24, sectorData, 2324);
            compute_edcecc(ptr);
            m_out->writeAt(std::move(slice), lba * IEC60908b::FRAMESIZE_RAW);
            break;
        default:
            return {0, 0, 0};
    }
    auto ret = msf;
    msf++;
    if (msf > m_location) m_location = msf;
    return ret;
}
