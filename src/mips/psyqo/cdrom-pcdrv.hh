/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

#include <EASTL/fixed_string.h>

#include "cdrom.hh"
#include "common/kernel/pcdrv.h"

namespace psyqo {
class CDRomPCDrv final : public CDRom {
  public:
    // instead of eagerly opening in the constructor:
    CDRomPCDrv(const char *isoName) : m_isoName(isoName) {}

    bool ensureOpen() {
        if (m_isoHandle < 0) {
            PCinit();
            m_isoHandle = PCopen(m_isoName.c_str(), 0, 0);
        }
        return m_isoHandle >= 0;
    }

    void readSectors(uint32_t sector, uint32_t count, void *buffer, eastl::function<void(bool)> &&callback) override;

  private:
    int m_isoHandle = -1;
    eastl::fixed_string<char, 256> m_isoName;
};
}  // namespace psyqo
