#pragma once

#include <stdint.h>

// Minimal, table-free UTF-8 codepoint decoder. Split out of sjis-encode.h so
// that the lightweight (no conversion table) code paths can decode UTF-8
// without dragging in the ~28kB Shift-JIS encoding table. Usable from both the
// host and the MIPS targets.

namespace Sjis {

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

}  // namespace Sjis
