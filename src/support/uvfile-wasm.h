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

// The wasm build drops uvfile.cc entirely: there is no libuv, no async I/O and
// no download path. This supplies a UvFile NAME backed by PosixFile so the ~30
// call sites on the v1 path - the cdriso readers, isobrowser, memcard_manager,
// the logfile, savestate writing, luafile's plain open modes - compile unchanged.
//
// WHAT IS DELIBERATELY ABSENT, and it is the whole design: no DOWNLOAD_URL, no
// UvFifo, no UvFifoListener, no two-argument startCaching. Every call site that
// wants one of those is a v1-dropped feature (the auto-updater, the SIO1 server,
// the Lua download/fifo bindings), and it must FAIL TO COMPILE here rather than
// receive a silent no-op. A no-op download returns success having fetched
// nothing, and that is a runtime-only failure on a build with no debugger.

#include <filesystem>

#include "support/file.h"

namespace PCSX {

class UvFile : public PosixFile {
  public:
    using PosixFile::PosixFile;

    // PosixFile declares `write(const void*, size_t)` as a final override, which
    // NAME-HIDES File's other write overloads - File::write(Slice&&) at file.h:81
    // and the write(T) template at :215. main.cc:63 does m_logfile->write(
    // std::move(s)) and got "too few arguments to function call, expected 2,
    // have 1". Un-hide them; UvFile inherits from File through a path that never
    // had this problem.
    using File::write;
    using PosixFile::write;

    // Caching is what UvFile does with a background libuv thread. A PosixFile is
    // already synchronous, so the cache is complete the moment it is asked for.
    void startCaching() {}
    float cacheProgress() { return 1.0f; }

    // Read from the "UvFiles" debug panel in gui.cc, which v1 does not build.
    // Present so the panel is a scoping decision rather than a link error.
    static float getReadRate() { return 0.0f; }
    static float getWriteRate() { return 0.0f; }
    static float getDownloadRate() { return 0.0f; }
};

// main.cc:178 declares `PCSX::UvThreadOp::UvThread uvThread;` - an RAII guard
// that starts and joins the libuv worker thread. On wasm there is no such thread,
// so an empty guard is the CORRECT semantic rather than a silenced failure.
//
// Deliberately NOT provided: iterateOverAllOps() and request(). Those marshal
// real work onto that thread, and a no-op version would drop the work while
// reporting success. isobrowser.cc:539 uses iterateOverAllOps for its caching
// progress UI and will fail to compile here, which is right - it is a v1-dropped
// widget, and that should be a scoping decision rather than a silent nothing.
struct UvThreadOp {
    struct UvThread {
        UvThread() = default;
        ~UvThread() = default;
        // Real one sets a flag so ~UvThread skips stopThread() on a crash path,
        // avoiding a deadlock joining a thread that may be wedged (main.cc:478).
        // With no thread there is nothing to skip joining.
        void setEmergencyExit() {}
    };
};

}  // namespace PCSX
