/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

struct SDL_Window;

namespace PCSX {

// Small per-platform GL/windowing shims that differ between desktop GL and
// Emscripten's WebGL/browser environment.
namespace GUIPlatform {

// Clears the GL depth buffer to `d`. Desktop GL and WebGL2/ES3 expose this
// through different entry points; see the two implementation files for why.
void clearDepth(double d);

// Presents the frame that was just rendered into `window`'s GL context.
void presentFrame(SDL_Window* window);

}  // namespace GUIPlatform

}  // namespace PCSX
