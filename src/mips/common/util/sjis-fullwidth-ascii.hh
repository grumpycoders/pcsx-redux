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

#include <stdint.h>

// Lightweight default title encoder: the ASCII-only subset of the BIOS
// save-title convention. Printable ASCII is promoted to its fullwidth form and
// looked up in a compact 95-entry table (190 bytes) carved out of the full
// Unicode->Shift-JIS table; any non-ASCII codepoint becomes '?'. This is what
// lets a program that only ever uses ASCII titles avoid linking the ~28kB
// c_unicodeToSjisConvTable. Registering the full encoder (see
// sjis-title-encoder.h) overrides this with the complete conversion.
//
// The table below is generated: for each ASCII value 0x20..0x7e it holds the
// Shift-JIS encoding of the corresponding fullwidth codepoint (space -> U+3000,
// 0x21..0x7e -> U+ff01..U+ff5e), taken verbatim from c_unicodeToSjisConvTable.
// Five fullwidth punctuation forms (" ' - \ ~) have no JIS X 0208 mapping, so
// their entries are 0 and the encoder emits '?' for them -- identical to what
// the full encoder does, keeping ASCII output byte-for-byte the same either way.

namespace Sjis {

// Indexed by (ASCII codepoint - 0x20), so [0] is space and [94] is '~'.
extern const uint16_t c_fullwidthAsciiToSjis[96];

// Encodes a UTF-8 string to Shift-JIS using the BIOS save-title convention,
// but with ASCII-only support: printable ASCII is promoted to fullwidth via the
// table above; every non-ASCII codepoint (and the five unmapped fullwidth forms)
// becomes '?'. Writes up to dstSize bytes, returns the number written; output is
// not NUL-terminated. Signature matches Sjis::utf8ToSjisTitle so the two are
// interchangeable behind a function pointer.
uint32_t asciiToSjisTitle(uint8_t* dst, uint32_t dstSize, const char* src);

// Decodes a Shift-JIS save title back to plain ASCII, the inverse of
// asciiToSjisTitle: each fullwidth form in the compact table becomes its ASCII
// character, and anything else (real Japanese, halfwidth kana, an unmapped
// form) becomes '?'. It uses only the 190-byte fullwidth table, so an ASCII-only
// program can read titles back without linking the full ~28kB conversion table;
// Sjis::sjisToUtf8 (sjis-decode.h) is the full-Unicode counterpart. Writes at
// most dstSize bytes, always NUL-terminating when dstSize > 0, and returns the
// number written (not counting the terminator). A 0x00 byte ends the input
// (0x00 is never a Shift-JIS lead or trail byte), giving a C string for the
// padded 64-byte card title field.
uint32_t sjisTitleToAscii(char* dst, uint32_t dstSize, const uint8_t* src, uint32_t srcLen);

}  // namespace Sjis
