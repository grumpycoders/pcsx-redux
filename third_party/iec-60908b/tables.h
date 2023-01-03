/*

MIT License

Copyright (c) 2022 Nicolas "Pixel" Noble

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

// Lookup table for the yellow book's crc32
extern const uint32_t yellow_book_crctable[256];

// Lookup tables for Galois field's exponent and logarithmic operations
extern const uint8_t gf_exp_table[512];
extern const uint8_t gf_log_table[256];

// Lookup tables for Galois field's multiplication by 2, and division by 3
extern const uint8_t gf_mul2_table[256];
extern const uint8_t gf_div3_table[256];

// references for copy/paste:
// ΣΠ·⁰¹²³⁴⁵⁶⁷⁸⁹ⁿ
