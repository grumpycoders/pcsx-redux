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

#include "psyqo/gte-math.hh"

#include "psyqo/soft-math.hh"

using namespace psyqo::fixed_point_literals;

// Everything else in GteMath is in the header, because psyqo builds at -Os and
// GCC will not inline the GTE register accessors there - it emits jal into
// writeSafe/read, measured at up to +67% on the per-call numbers. This one is
// out of line only because it calls into SoftMath for the Newton refinement,
// and the refinement is arithmetic rather than register traffic.
void psyqo::GteMath::normalizeVec3(Vec3 *v) {
    FixedPoint<> square = v->x * v->x + v->y * v->y + v->z * v->z;
    // SoftMath::squareRoot returns 0 for raw() <= 1 and normalizeVec3 then
    // divides by it, so degenerate input has to be caught here rather than
    // handed on.
    if (square.raw() <= 1) {
        *v = {0.0_fp, 0.0_fp, 1.0_fp};
        return;
    }
    FixedPoint<> len = SoftMath::inverseSquareRoot(square, inverseSquareRootSeed(square));
    v->x *= len;
    v->y *= len;
    v->z *= len;
}
