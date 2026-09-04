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

#ifdef __EMSCRIPTEN__

#include "gui/gui-platform.h"

#include <GL/gl3w.h>
#include <SDL3/SDL.h>
#include <emscripten/html5_webgl.h>

namespace PCSX {
namespace GUIPlatform {

// glClearDepth takes a double and is desktop-GL only; ES3 and WebGL2 have only
// the float form, glClearDepthf. gl3w resolves the desktop name to NULL there,
// which now lands in a typed thrower and surfaces as "gl function not loaded" -
// the two occurrences were exactly the two call sites in gui.cc that now go
// through GUIPlatform::clearDepth.
void clearDepth(double d) { glClearDepthf(static_cast<float>(d)); }

void presentFrame(SDL_Window* window) {
    SDL_GL_SwapWindow(window);
    // Nothing in the SDL or EGL path presents a frame in a browser: emscripten's
    // eglSwapBuffers is a no-op, and a WebGL canvas is normally composited only
    // when the owning thread's task ENDS. main() runs on a proxied pthread here
    // and its loop never returns, so without this call the browser never sees a
    // single frame - measured with a four-arm oracle in which an identical
    // program drew 208,800 frames to a canvas that stayed black, and the same
    // program with one `return` after 300 frames came up magenta.
    // This is the escape hatch: with -sOFFSCREEN_FRAMEBUFFER the context renders
    // to an offscreen backbuffer that commit_frame blits to the real canvas on
    // the browser main thread, whose event loop is turning normally. It is what
    // lets the blocking main loop stand for v1.
    emscripten_webgl_commit_frame();
}

}  // namespace GUIPlatform
}  // namespace PCSX

#endif  // __EMSCRIPTEN__
