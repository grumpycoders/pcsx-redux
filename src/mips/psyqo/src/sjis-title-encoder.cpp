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

// Definition of the active save-title encoder pointer. This translation unit is
// always linked (the filesystem references g_titleEncoder), and it deliberately
// pulls in only the lightweight ASCII encoder -- never the ~28kB conversion
// table. The full encoder lives in sjis-full-title-encoder.cpp and is reached
// only through Sjis::registerFullTitleEncoder().

#include "common/util/sjis-title-encoder.h"

#include "common/util/sjis-fullwidth-ascii.h"

namespace Sjis {

TitleEncoder g_titleEncoder = &asciiToSjisTitle;

}  // namespace Sjis
