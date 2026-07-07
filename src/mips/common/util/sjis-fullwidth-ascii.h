#pragma once

#include <stdint.h>

#include "common/util/utf8-decode.h"

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
static const uint16_t c_fullwidthAsciiToSjis[95] = {
    0x8140, 0x8149, 0x0000, 0x8194, 0x8190, 0x8193, 0x8195, 0x0000, 0x8169, 0x816a, 0x8196,
    0x817b, 0x8143, 0x0000, 0x8144, 0x815e, 0x824f, 0x8250, 0x8251, 0x8252, 0x8253, 0x8254,
    0x8255, 0x8256, 0x8257, 0x8258, 0x8146, 0x8147, 0x8183, 0x8181, 0x8184, 0x8148, 0x8197,
    0x8260, 0x8261, 0x8262, 0x8263, 0x8264, 0x8265, 0x8266, 0x8267, 0x8268, 0x8269, 0x826a,
    0x826b, 0x826c, 0x826d, 0x826e, 0x826f, 0x8270, 0x8271, 0x8272, 0x8273, 0x8274, 0x8275,
    0x8276, 0x8277, 0x8278, 0x8279, 0x816d, 0x0000, 0x816e, 0x814f, 0x8151, 0x814d, 0x8281,
    0x8282, 0x8283, 0x8284, 0x8285, 0x8286, 0x8287, 0x8288, 0x8289, 0x828a, 0x828b, 0x828c,
    0x828d, 0x828e, 0x828f, 0x8290, 0x8291, 0x8292, 0x8293, 0x8294, 0x8295, 0x8296, 0x8297,
    0x8298, 0x8299, 0x829a, 0x816f, 0x8162, 0x8170, 0x0000,
};

// Encodes a UTF-8 string to Shift-JIS using the BIOS save-title convention,
// but with ASCII-only support: printable ASCII is promoted to fullwidth via the
// table above; every non-ASCII codepoint (and the five unmapped fullwidth forms)
// becomes '?'. Writes up to dstSize bytes, returns the number written; output is
// not NUL-terminated. Signature matches Sjis::utf8ToSjisTitle so the two are
// interchangeable behind a function pointer.
static inline uint32_t asciiToSjisTitle(uint8_t* dst, uint32_t dstSize, const char* src) {
    uint32_t srcLen = 0;
    while (src[srcLen]) srcLen++;
    uint32_t in = 0, out = 0;
    while (in < srcLen && out < dstSize) {
        uint16_t cp = utf8Decode(src, srcLen, &in);
        uint16_t sjis;
        if (cp == ' ') {
            sjis = c_fullwidthAsciiToSjis[0];
        } else if (cp >= 0x21 && cp <= 0x7e) {
            sjis = c_fullwidthAsciiToSjis[cp - 0x20];
        } else {
            sjis = 0;
        }
        if (sjis == 0) sjis = '?';
        if (sjis > 0xff) {
            if (out + 2 > dstSize) break;
            dst[out++] = sjis >> 8;
            dst[out++] = sjis & 0xff;
        } else {
            dst[out++] = sjis & 0xff;
        }
    }
    return out;
}

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
static inline uint32_t sjisTitleToAscii(char* dst, uint32_t dstSize, const uint8_t* src, uint32_t srcLen) {
    if (dstSize == 0) return 0;
    uint32_t out = 0;
    for (uint32_t i = 0; i < srcLen; i++) {
        uint8_t c = src[i];
        if (c == 0) break;
        char ch;
        unsigned hi = c >> 4;
        if (hi == 8 || hi == 9 || hi == 14) {
            // Two-byte lead: reverse-lookup its fullwidth mapping.
            if (++i >= srcLen) break;  // truncated trailing lead byte: drop it.
            uint16_t sjis = (static_cast<uint16_t>(c) << 8) | src[i];
            ch = '?';
            for (unsigned k = 0; k < 95; k++) {
                if (c_fullwidthAsciiToSjis[k] == sjis) {
                    ch = static_cast<char>(0x20 + k);
                    break;
                }
            }
        } else if (c >= 0x20 && c <= 0x7e) {
            ch = static_cast<char>(c);  // already plain ASCII: pass through.
        } else {
            ch = '?';
        }
        if (out + 1 >= dstSize) break;
        dst[out++] = ch;
    }
    dst[out] = '\0';
    return out;
}

}  // namespace Sjis
