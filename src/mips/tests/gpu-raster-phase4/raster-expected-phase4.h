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

// Phase-4 expected hardware-truth values for textured-triangle tests.
//
// Uses fixtures from texture-fixtures.h. Tests draw textured triangles
// where vertex UV coords match the screen position 1:1, so a pixel at
// screen (x, y) samples texel at (x, y). For 4-bit and 8-bit CLUT
// textures, that texel is then looked up in the CLUT and produces a
// known VRAM 5:5:5 color. For 15-bit direct, the texel itself is the
// VRAM color.
//
// Expected values use the `expectedClutN/expectedTex15` helpers in
// texture-fixtures.h. They're not literal macros because rasterVram555
// is not a constant expression - tests inline the helper call.

#include "texture-fixtures.h"
