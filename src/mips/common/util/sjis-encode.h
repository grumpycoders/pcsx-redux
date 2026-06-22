#pragma once

#include <stdint.h>

#include "common/util/sjis-encode-table.h"

// Unicode -> Shift-JIS encoding, the inverse of support/sjis_conv.cc's decoder.
// Shares the same data as the forward table (sjis-table.h), inverted into
// sjis-encode-table.h. Usable from both the host and the MIPS targets.

namespace Sjis {

// Returns the Shift-JIS encoding of a Unicode codepoint, or 0 if it has no
// mapping. A result <= 0xff is a single byte; otherwise it is two bytes, high
// byte first. (U+0000 also returns 0, which is harmless for string use.)
static inline uint16_t unicodeToSjis(uint16_t unicode) {
    unsigned lo = 0, hi = sizeof(c_unicodeToSjisConvTable) / sizeof(c_unicodeToSjisConvTable[0]);
    while (lo < hi) {
        unsigned mid = (lo + hi) / 2;
        uint16_t u = c_unicodeToSjisConvTable[mid].unicode;
        if (u == unicode) return c_unicodeToSjisConvTable[mid].sjis;
        if (u < unicode) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return 0;
}

// Decodes one UTF-8 codepoint from str, advancing *index. Returns the codepoint,
// or 0xfffd (replacement) on a malformed sequence. Codepoints above the BMP are
// returned truncated to 0xfffd since Shift-JIS cannot represent them.
static inline uint16_t utf8Decode(const char* str, uint32_t length, uint32_t* index) {
    uint32_t i = *index;
    uint8_t c = str[i++];
    uint32_t cp;
    unsigned extra;
    if (c < 0x80) {
        *index = i;
        return c;
    } else if ((c & 0xe0) == 0xc0) {
        cp = c & 0x1f;
        extra = 1;
    } else if ((c & 0xf0) == 0xe0) {
        cp = c & 0x0f;
        extra = 2;
    } else {
        *index = i;
        return 0xfffd;
    }
    for (unsigned k = 0; k < extra; k++) {
        if (i >= length || (str[i] & 0xc0) != 0x80) {
            *index = i;
            return 0xfffd;
        }
        cp = (cp << 6) | (str[i++] & 0x3f);
    }
    *index = i;
    return cp > 0xffff ? 0xfffd : (uint16_t)cp;
}

// Encodes a UTF-8 C string to Shift-JIS. Writes up to dstSize bytes and returns
// the number written. Codepoints with no Shift-JIS mapping are emitted as '?'.
// The output is not NUL-terminated.
static inline uint32_t utf8ToSjis(uint8_t* dst, uint32_t dstSize, const char* src) {
    uint32_t srcLen = 0;
    while (src[srcLen]) srcLen++;
    uint32_t in = 0, out = 0;
    while (in < srcLen && out < dstSize) {
        uint16_t cp = utf8Decode(src, srcLen, &in);
        uint16_t sjis = unicodeToSjis(cp);
        if (sjis == 0 && cp != 0) sjis = '?';
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

// Encodes a UTF-8 string to Shift-JIS using the BIOS save-title convention:
// printable ASCII is promoted to its fullwidth form (space -> U+3000,
// 0x21..0x7e -> U+ff01..U+ff5e) so it renders in the manager's fullwidth font,
// while any non-ASCII codepoint (e.g. Japanese) is encoded directly. This is
// what memory card save titles want. Writes up to dstSize bytes, returns the
// number written; output is not NUL-terminated.
static inline uint32_t utf8ToSjisTitle(uint8_t* dst, uint32_t dstSize, const char* src) {
    uint32_t srcLen = 0;
    while (src[srcLen]) srcLen++;
    uint32_t in = 0, out = 0;
    while (in < srcLen && out < dstSize) {
        uint16_t cp = utf8Decode(src, srcLen, &in);
        if (cp == ' ') {
            cp = 0x3000;
        } else if (cp >= 0x21 && cp <= 0x7e) {
            cp = 0xff00 + (cp - 0x20);
        }
        uint16_t sjis = unicodeToSjis(cp);
        if (sjis == 0 && cp != 0) sjis = '?';
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

}  // namespace Sjis
