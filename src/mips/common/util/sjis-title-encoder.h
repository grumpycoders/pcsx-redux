#pragma once

#include <stdint.h>

// Registration seam for the memory-card save-title encoder.
//
// The filesystem encodes save titles through the g_titleEncoder function
// pointer, which defaults to the lightweight ASCII-only encoder
// (Sjis::asciiToSjisTitle, ~190 bytes of table). A program that needs to write
// non-ASCII (e.g. Japanese) titles calls registerFullTitleEncoder() once at
// startup to swap in the complete UTF-8 -> Shift-JIS converter. Because the
// full encoder and its ~28kB table live in their own translation unit and are
// only reachable through registerFullTitleEncoder(), --gc-sections drops the
// table entirely from any program that never calls it.

namespace Sjis {

using TitleEncoder = uint32_t (*)(uint8_t* dst, uint32_t dstSize, const char* src);

// The active title encoder. Defaults to Sjis::asciiToSjisTitle.
extern TitleEncoder g_titleEncoder;

// Installs the full UTF-8 -> Shift-JIS title encoder (pulls in the ~28kB
// conversion table). Call once, before writing any non-ASCII title.
void registerFullTitleEncoder();

}  // namespace Sjis
