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

#include "binpath.h"

#if defined(__APPLE__) && defined(__MACH__)

#include <CoreFoundation/CoreFoundation.h>

#include <stdexcept>

std::u8string PCSX::BinPath::getExecutablePath() {
    CFBundleRef mainBundle = CFBundleGetMainBundle();
    CFURLRef execURL = CFBundleCopyExecutableURL(mainBundle);
    char8_t path[PATH_MAX];
    if (!CFURLGetFileSystemRepresentation(execURL, TRUE, (UInt8 *)path, PATH_MAX)) {
        throw std::runtime_error("Could not get executable path");
    }
    CFRelease(execURL);
    return std::u8string(path);
}

#endif
