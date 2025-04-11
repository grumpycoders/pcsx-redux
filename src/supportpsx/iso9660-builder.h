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

#pragma once

#include "support/file.h"
#include "supportpsx/iec-60908b.h"

namespace PCSX {

class ISO9660Builder {
  public:
    ISO9660Builder(IO<File> out) : m_out(out) {}
    bool failed() { return !m_out || m_out->failed(); }
    IEC60908b::MSF getCurrentLocation() { return m_location; }
    void writeLicense(IO<File> licenseFile = nullptr);
    IEC60908b::MSF writeSector(const uint8_t* sectorData, IEC60908b::SectorMode mode) {
        return writeSectorAt(sectorData, m_location++, mode);
    }
    IEC60908b::MSF writeSectorAt(const uint8_t* sectorData, IEC60908b::MSF msf, IEC60908b::SectorMode mode);
    void close() {
        m_out->close();
        m_out = nullptr;
    }

  private:
    IO<File> m_out;
    IEC60908b::MSF m_location = {0, 2, 0};
};

}  // namespace PCSX
