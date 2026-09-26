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

#ifndef __EMSCRIPTEN__

#include "gui/gui-platform.h"

#include <GL/gl3w.h>
#include <SDL3/SDL.h>

namespace PCSX {
namespace GUIPlatform {

// Not unconditionally glClearDepthf: that one needs GL 4.1 or
// ARB_ES2_compatibility, and Redux asks for a 3.2 core context, so on desktop it
// can be the absent one instead.
void clearDepth(double d) { glClearDepth(d); }

void presentFrame(SDL_Window* window) { SDL_GL_SwapWindow(window); }

}  // namespace GUIPlatform
}  // namespace PCSX

#endif  // __EMSCRIPTEN__
