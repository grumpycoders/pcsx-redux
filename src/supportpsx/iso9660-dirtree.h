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

#include <string>
#include <string_view>

#include "support/file.h"
#include "supportpsx/iec-60908b.h"
#include "supportpsx/iso9660-lowlevel.h"

namespace PCSX {
class ISO9660Builder;

namespace ISO9660 {

class DirTree {
  public:
    // Tree navigation
    DirTree* parent() const { return m_parent; }
    DirTree* firstChild() const { return m_firstChild; }
    DirTree* nextSibling() const { return m_nextSibling; }

    // Property access
    std::string_view getName() const { return m_name; }
    bool isDir() const { return m_isDir; }
    uint32_t getLBA() const { return m_assignedLBA; }
    uint32_t getSize() const { return m_computedSize; }

    // Flags
    bool isHidden() const { return m_hidden; }
    void setHidden(bool hidden) { m_hidden = hidden; }

    // Don't write this entry to the parent directory, but still write its content
    bool shouldSkip() const { return m_skip; }
    void setSkip(bool skip) { m_skip = skip; }

    // Layout anchor: force this entry's content to start at the specified LBA. At
    // close() time, any prior gap sectors are filled with empty Mode 2 Form 1 zero
    // sectors. ISO9660Builder::close() throws if layout has already advanced past the
    // anchor LBA by the time this entry is reached.
    bool hasAnchorLBA() const { return m_hasAnchor; }
    uint32_t getAnchorLBA() const { return m_anchorLBA; }
    void setAnchorLBA(uint32_t lba) {
        m_anchorLBA = lba;
        m_hasAnchor = true;
    }
    void clearAnchorLBA() {
        m_anchorLBA = 0;
        m_hasAnchor = false;
    }

    // Declared-size override: the ISO9660 directory-entry Length field uses this value
    // instead of the actual content size when set. Allows a single entry to "shadow" a
    // larger extent than what is written under it, which is useful when other entries
    // are marked with setSkip and laid out at known LBAs inside the same extent.
    bool hasDeclaredSize() const { return m_hasDeclaredSize; }
    uint32_t getDeclaredSize() const { return m_declaredSize; }
    void setDeclaredSize(uint32_t size) {
        m_declaredSize = size;
        m_hasDeclaredSize = true;
    }
    void clearDeclaredSize() {
        m_declaredSize = 0;
        m_hasDeclaredSize = false;
    }

    // XA extensions
    bool hasXA() const { return m_hasXA; }
    void setHasXA(bool xa) { m_hasXA = xa; }
    ISO9660LowLevel::DirEntry_XA& getXA() { return m_xa; }
    const ISO9660LowLevel::DirEntry_XA& getXA() const { return m_xa; }

    // Sector mode for this entry's data
    IEC60908b::SectorMode getSectorMode() const { return m_sectorMode; }
    void setSectorMode(IEC60908b::SectorMode mode) { m_sectorMode = mode; }

    // Date (ShortDate used in directory records)
    ISO9660LowLevel::ShortDate& getDate() { return m_date; }
    const ISO9660LowLevel::ShortDate& getDate() const { return m_date; }

    // File content handle (only meaningful for files)
    IO<File> getContent() const { return m_content; }

    // Default constructor - only IsoBuilder should create nodes, but public for make_unique.
    DirTree() = default;

  private:
    friend class ::PCSX::ISO9660Builder;

    // Identity
    std::string m_name;
    bool m_isDir = true;

    // Tree links (raw pointers - IsoBuilder owns all nodes)
    DirTree* m_parent = nullptr;
    DirTree* m_firstChild = nullptr;
    DirTree* m_nextSibling = nullptr;

    // Serializable metadata
    ISO9660LowLevel::ShortDate m_date;
    ISO9660LowLevel::DirEntry_XA m_xa;
    bool m_hasXA = false;
    bool m_hidden = false;
    bool m_skip = false;

    // Sector mode for writing this entry's content
    IEC60908b::SectorMode m_sectorMode = IEC60908b::SectorMode::M2_FORM1;

    // File content (files only)
    IO<File> m_content;

    // Directory extent allocation (directories only)
    unsigned m_dirSectorCount = 1;

    // Layout fields (computed at close time)
    uint32_t m_assignedLBA = 0;
    uint32_t m_computedSize = 0;
    uint16_t m_pathTableIndex = 0;

    // Optional layout overrides (see public setters above).
    uint32_t m_anchorLBA = 0;
    bool m_hasAnchor = false;
    uint32_t m_declaredSize = 0;
    bool m_hasDeclaredSize = false;
};

}  // namespace ISO9660
}  // namespace PCSX
