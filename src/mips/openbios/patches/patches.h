/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include "common/compiler/stdint.h"

/*
  Most PSX games will have kernel patches within them. Most (but not all)
  of these patches will call B0:56 and B0:57 to get the pointer of the
  B0 and C0 tables. It will be close to impossible for us to create code
  in a way that will make these patches work properly transparently, so
  instead we will rely on the fact they are calling these two functions,
  and then we patch them out after we detect them. This assumes that these
  two functions aren't called for anything else but the patches. The
  boolean below controls if we want to be permissive or not with unrecognized
  patches. It is currently set to 1, and probably should remain so for a
  long time, until we are sure we got all the patches properly.

  Then, depending on the patch itself, we may change our kernel's behavior,
  in order to emulate what the original patch was trying to do.
*/

extern int g_patch_permissive;

enum patch_table { PATCH_TABLE_B0, PATCH_TABLE_C0 };
void patch_hook(uint32_t* ra, enum patch_table table);
