/*

MIT License

Copyright (c) 2026 Nicolas "Pixel" Noble

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

#ifdef __cplusplus
extern "C" {
#endif

// Recompute the sector's EDC and compare it to the stored value. Returns 1 if
// the EDC matches (the user data is intact), 0 otherwise. Works for Mode 2
// Form 1 and Form 2; any other sector type returns 1.
int check_edc(const uint8_t* sector);

// Attempt to repair a Mode 2 Form 1 sector in place using its P and Q ECC,
// iterating the two channels until the EDC validates or no further progress is
// possible. Returns:
//    1  the sector is valid (was already clean, or was corrected)
//    0  the sector could not be brought to a valid EDC (too much damage)
// Form 2 sectors carry no ECC, so this returns whatever check_edc reports.
// Non-Mode-2 sectors are left untouched and report 1.
int correct_sector(uint8_t* sector);

#ifdef __cplusplus
}
#endif
