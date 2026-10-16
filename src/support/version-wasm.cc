/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

// The updater, stubbed for wasm. version.cc is the common implementation and is
// disabled here: it downloads over libcurl through UvFile's DOWNLOAD_URL mode,
// and the wasm UvFile shim deliberately does not have that mode.
//
// EVERY DOWNLOAD ENTRY POINT RETURNS false, NOT true. A no-op that reports
// success has fetched nothing and said it worked, which on a build with no
// debugger is a runtime-only failure. Failing is the correct semantic: there is
// no update mechanism here, and callers already handle being told so.
#ifdef __EMSCRIPTEN__

#include "support/version.h"

void PCSX::VersionInfo::loadFromFile(IO<File> file) {}

float PCSX::Update::progress() { return 0.0f; }

bool PCSX::Update::downloadUpdateInfo(const VersionInfo &, std::function<void(bool)> callback, uv_loop_t *) {
    if (callback) callback(false);
    return false;
}

bool PCSX::Update::downloadAndApplyUpdate(const VersionInfo &, std::function<void(bool)> callback, uv_loop_t *) {
    if (callback) callback(false);
    return false;
}

bool PCSX::Update::getDownloadUrl(const VersionInfo &, std::function<void(std::string)> callback, uv_loop_t *) {
    if (callback) callback("");
    return false;
}

// The platform half, which on every other target lives in version-<os>.cc.
bool PCSX::Update::canFullyApply() { return false; }
bool PCSX::Update::applyUpdate(const std::filesystem::path &) { return false; }

#endif
