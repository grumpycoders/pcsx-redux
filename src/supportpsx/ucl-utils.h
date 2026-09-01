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

#include <cstddef>
#include <cstdint>
#include <optional>

#include "support/file.h"

namespace PCSX::UCLUtils {

// Returns the exact number of bytes the compressed NRV2E stream must sit above
// the decompression target for safe in-place (overlapping) decompression, i.e.
// the smallest src_off for which decoding &buf[src_off] -> &buf[0] never lets
// the write head overtake the read head. `src`/`srcLen` is the compressed
// stream; `expectedDstLen` is the uncompressed size. Throws std::runtime_error
// on a malformed stream.
size_t inPlaceOverlapMargin(const uint8_t* src, size_t srcLen, size_t expectedDstLen);

}  // namespace PCSX::UCLUtils
