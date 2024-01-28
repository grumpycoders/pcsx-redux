/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

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

#include "psyqo/soft-math.hh"

using namespace psyqo::fixed_point_literals;
using namespace psyqo::trig_literals;

void psyqo::SoftMath::generateRotationMatrix33(Matrix33 *m, Angle t, Axis a, Trig<> *trig) {
    auto s = trig->sin(t);
    auto c = trig->cos(t);
    switch (a) {
        case Axis::X:
            m->vs[0].x = 1.0_fp;
            m->vs[0].y = 0.0_fp;
            m->vs[0].z = 0.0_fp;
            m->vs[1].x = 0.0_fp;
            m->vs[1].y = c;
            m->vs[1].z = s;
            m->vs[2].x = 0.0_fp;
            m->vs[2].y = -s;
            m->vs[2].z = c;
            break;
        case Axis::Y:
            m->vs[0].x = c;
            m->vs[0].y = 0.0_fp;
            m->vs[0].z = -s;
            m->vs[1].x = 0.0_fp;
            m->vs[1].y = 1.0_fp;
            m->vs[1].z = 0.0_fp;
            m->vs[2].x = s;
            m->vs[2].y = 0.0_fp;
            m->vs[2].z = c;
            break;
        case Axis::Z:
            m->vs[0].x = c;
            m->vs[0].y = s;
            m->vs[0].z = 0.0_fp;
            m->vs[1].x = -s;
            m->vs[1].y = c;
            m->vs[1].z = 0.0_fp;
            m->vs[2].x = 0.0_fp;
            m->vs[2].y = 0.0_fp;
            m->vs[2].z = 1.0_fp;
            break;
    }
}

psyqo::Matrix33 psyqo::SoftMath::generateRotationMatrix33(Angle t, Axis a, Trig<> *trig) {
    auto s = trig->sin(t);
    auto c = trig->cos(t);
    switch (a) {
        case Axis::X: {
            return Matrix33{{{
                                 .x = 1.0_fp,
                                 .y = 0.0_fp,
                                 .z = 0.0_fp,
                             },
                             {
                                 .x = 0.0_fp,
                                 .y = c,
                                 .z = s,
                             },
                             {
                                 .x = 0.0_fp,
                                 .y = -s,
                                 .z = c,
                             }}};
        } break;
        case Axis::Y: {
            return Matrix33{{{
                                 .x = c,
                                 .y = 0.0_fp,
                                 .z = -s,
                             },
                             {
                                 .x = 0.0_fp,
                                 .y = 1.0_fp,
                                 .z = 0.0_fp,
                             },
                             {
                                 .x = s,
                                 .y = 0.0_fp,
                                 .z = c,
                             }}};
        } break;
        case Axis::Z: {
            return Matrix33{{{
                                 .x = c,
                                 .y = s,
                                 .z = 0.0_fp,
                             },
                             {
                                 .x = -s,
                                 .y = c,
                                 .z = 0.0_fp,
                             },
                             {
                                 .x = 0.0_fp,
                                 .y = 0.0_fp,
                                 .z = 1.0_fp,
                             }}};
        } break;
    }
    __builtin_unreachable();
}

void psyqo::SoftMath::multiplyMatrix33(const Matrix33 *m1, const Matrix33 *m2, Matrix33 *out) {
    auto x0 = m1->vs[0].x * m2->vs[0].x + m1->vs[1].x * m2->vs[0].y + m1->vs[2].x * m2->vs[0].z;
    auto y0 = m1->vs[0].y * m2->vs[0].x + m1->vs[1].y * m2->vs[0].y + m1->vs[2].y * m2->vs[0].z;
    auto z0 = m1->vs[0].z * m2->vs[0].x + m1->vs[1].z * m2->vs[0].y + m1->vs[2].z * m2->vs[0].z;
    auto x1 = m1->vs[0].x * m2->vs[1].x + m1->vs[1].x * m2->vs[1].y + m1->vs[2].x * m2->vs[1].z;
    auto y1 = m1->vs[0].y * m2->vs[1].x + m1->vs[1].y * m2->vs[1].y + m1->vs[2].y * m2->vs[1].z;
    auto z1 = m1->vs[0].z * m2->vs[1].x + m1->vs[1].z * m2->vs[1].y + m1->vs[2].z * m2->vs[1].z;
    auto x2 = m1->vs[0].x * m2->vs[2].x + m1->vs[1].x * m2->vs[2].y + m1->vs[2].x * m2->vs[2].z;
    auto y2 = m1->vs[0].y * m2->vs[2].x + m1->vs[1].y * m2->vs[2].y + m1->vs[2].y * m2->vs[2].z;
    auto z2 = m1->vs[0].z * m2->vs[2].x + m1->vs[1].z * m2->vs[2].y + m1->vs[2].z * m2->vs[2].z;

    out->vs[0].x = x0;
    out->vs[0].y = y0;
    out->vs[0].z = z0;
    out->vs[1].x = x1;
    out->vs[1].y = y1;
    out->vs[1].z = z1;
    out->vs[2].x = x2;
    out->vs[2].y = y2;
    out->vs[2].z = z2;
}

psyqo::Matrix33 psyqo::SoftMath::multiplyMatrix33(const Matrix33 *m1, const Matrix33 *m2) {
    auto x0 = m1->vs[0].x * m2->vs[0].x + m1->vs[1].x * m2->vs[0].y + m1->vs[2].x * m2->vs[0].z;
    auto y0 = m1->vs[0].y * m2->vs[0].x + m1->vs[1].y * m2->vs[0].y + m1->vs[2].y * m2->vs[0].z;
    auto z0 = m1->vs[0].z * m2->vs[0].x + m1->vs[1].z * m2->vs[0].y + m1->vs[2].z * m2->vs[0].z;
    auto x1 = m1->vs[0].x * m2->vs[1].x + m1->vs[1].x * m2->vs[1].y + m1->vs[2].x * m2->vs[1].z;
    auto y1 = m1->vs[0].y * m2->vs[1].x + m1->vs[1].y * m2->vs[1].y + m1->vs[2].y * m2->vs[1].z;
    auto z1 = m1->vs[0].z * m2->vs[1].x + m1->vs[1].z * m2->vs[1].y + m1->vs[2].z * m2->vs[1].z;
    auto x2 = m1->vs[0].x * m2->vs[2].x + m1->vs[1].x * m2->vs[2].y + m1->vs[2].x * m2->vs[2].z;
    auto y2 = m1->vs[0].y * m2->vs[2].x + m1->vs[1].y * m2->vs[2].y + m1->vs[2].y * m2->vs[2].z;
    auto z2 = m1->vs[0].z * m2->vs[2].x + m1->vs[1].z * m2->vs[2].y + m1->vs[2].z * m2->vs[2].z;

    return Matrix33{{{.x = x0, .y = y0, .z = z0}, {.x = x1, .y = y1, .z = z1}, {.x = x2, .y = y2, .z = z2}}};
}

void psyqo::SoftMath::scaleMatrix33(Matrix33 *m, psyqo::FixedPoint<> s) {
    m->vs[0].x = m->vs[0].x * s;
    m->vs[0].y = m->vs[0].y * s;
    m->vs[0].z = m->vs[0].z * s;
    m->vs[1].x = m->vs[1].x * s;
    m->vs[1].y = m->vs[1].y * s;
    m->vs[1].z = m->vs[1].z * s;
    m->vs[2].x = m->vs[2].x * s;
    m->vs[2].y = m->vs[2].y * s;
    m->vs[2].z = m->vs[2].z * s;
}

void psyqo::SoftMath::matrixVecMul3(const Matrix33 *m, const Vec3 *v, Vec3 *out) {
    auto x = v->x;
    auto y = v->y;
    auto z = v->z;
    auto mx1 = m->vs[0].x;
    auto my1 = m->vs[0].y;
    auto mz1 = m->vs[0].z;
    auto mx2 = m->vs[1].x;
    auto my2 = m->vs[1].y;
    auto mz2 = m->vs[1].z;
    auto mx3 = m->vs[2].x;
    auto my3 = m->vs[2].y;
    auto mz3 = m->vs[2].z;
    auto nx1 = x * mx1;
    auto ny1 = y * my1;
    auto nz1 = z * mz1;
    auto nx2 = x * mx2;
    auto ny2 = y * my2;
    auto nz2 = z * mz2;
    auto nx3 = x * mx3;
    auto ny3 = y * my3;
    auto nz3 = z * mz3;
    auto nx = nx1 + ny1 + nz1;
    auto ny = nx2 + ny2 + nz2;
    auto nz = nx3 + ny3 + nz3;
    out->x = nx;
    out->y = ny;
    out->z = nz;
}

void psyqo::SoftMath::matrixVecMul3xy(const Matrix33 *m, const Vec3 *v, Vec2 *out) {
    auto x = v->x;
    auto y = v->y;
    auto z = v->z;
    auto mx1 = m->vs[0].x;
    auto my1 = m->vs[0].y;
    auto mz1 = m->vs[0].z;
    auto mx2 = m->vs[1].x;
    auto my2 = m->vs[1].y;
    auto mz2 = m->vs[1].z;
    auto nx1 = x * mx1;
    auto ny1 = y * my1;
    auto nz1 = z * mz1;
    auto nx2 = x * mx2;
    auto ny2 = y * my2;
    auto nz2 = z * mz2;
    auto nx = nx1 + ny1 + nz1;
    auto ny = nx2 + ny2 + nz2;
    out->x = nx;
    out->y = ny;
}

psyqo::FixedPoint<> psyqo::SoftMath::matrixVecMul3z(const Matrix33 *m, const Vec3 *v) {
    auto x = v->x;
    auto y = v->y;
    auto z = v->z;
    auto mx3 = m->vs[2].x;
    auto my3 = m->vs[2].y;
    auto mz3 = m->vs[2].z;
    auto nx3 = x * mx3;
    auto ny3 = y * my3;
    auto nz3 = z * mz3;
    return nx3 + ny3 + nz3;
}

void psyqo::SoftMath::crossProductVec3(const Vec3 *v1, const Vec3 *v2, Vec3 *out) {
    auto x1 = v1->x;
    auto y1 = v1->y;
    auto z1 = v1->z;
    auto x2 = v2->x;
    auto y2 = v2->y;
    auto z2 = v2->z;
    auto nx = y1 * z2 - z1 * y2;
    auto ny = z1 * x2 - x1 * z2;
    auto nz = x1 * y2 - y1 * x2;
    out->x = nx;
    out->y = ny;
    out->z = nz;
}

psyqo::Vec3 psyqo::SoftMath::crossProductVec3(const Vec3 *v1, const Vec3 *v2) {
    Vec3 out;
    auto x1 = v1->x;
    auto y1 = v1->y;
    auto z1 = v1->z;
    auto x2 = v2->x;
    auto y2 = v2->y;
    auto z2 = v2->z;
    auto nx = y1 * z2 - z1 * y2;
    auto ny = z1 * x2 - x1 * z2;
    auto nz = x1 * y2 - y1 * x2;
    out.x = nx;
    out.y = ny;
    out.z = nz;
    return out;
}

psyqo::FixedPoint<> psyqo::SoftMath::matrixDeterminant3(const Matrix33 *m) {
    auto x1 = m->vs[0].x;
    auto y1 = m->vs[0].y;
    auto z1 = m->vs[0].z;
    auto x2 = m->vs[1].x;
    auto y2 = m->vs[1].y;
    auto z2 = m->vs[1].z;
    auto x3 = m->vs[2].x;
    auto y3 = m->vs[2].y;
    auto z3 = m->vs[2].z;
    auto nx = x1 * (y2 * z3 - z2 * y3);
    auto ny = y1 * (x2 * z3 - z2 * x3);
    auto nz = z1 * (x2 * y3 - y2 * x3);
    return nx - ny + nz;
}

psyqo::FixedPoint<> psyqo::SoftMath::squareRoot(psyqo::FixedPoint<> x, psyqo::FixedPoint<> y) {
    if (x.raw() <= 1) return 0;
    auto x0 = y;
    auto x1 = x / x0;
    while ((x1 - x0).abs().raw() > 1) {
        x0 = (x0 + x1) / 2;
        x1 = x / x0;
    }
    return x0;
}

psyqo::FixedPoint<> psyqo::SoftMath::inverseSquareRoot(psyqo::FixedPoint<> x, psyqo::FixedPoint<> y) {
    // Newton method, using f(y) = 1/y² - x
    // Meaning we want to calculate y - f(y)/f'(y)
    // which expands into (y * (3 - xy²)) / 2, and simplifies to y * (3/2 - x/2 * y²)

    // It will converge only for x < 1 however.
    if (x > 1) return 1 / squareRoot(x, 1 / y);

    y *= (1.5_fp - (x * y * y) / 2);
    y *= (1.5_fp - (x * y * y) / 2);
    y *= (1.5_fp - (x * y * y) / 2);
    y *= (1.5_fp - (x * y * y) / 2);

    return y;
}

psyqo::FixedPoint<> psyqo::SoftMath::normOfVec3(const Vec3 *v) {
    auto x = v->x;
    auto y = v->y;
    auto z = v->z;
    auto s = x * x + y * y + z * z;
    return squareRoot(s);
}

void psyqo::SoftMath::normalizeVec3(Vec3 *v) {
    auto x = v->x;
    auto y = v->y;
    auto z = v->z;
    auto s = x * x + y * y + z * z;
    auto r = 1 / squareRoot(s);
    x *= r;
    y *= r;
    z *= r;
    v->x = x;
    v->y = y;
    v->z = z;
}

void psyqo::SoftMath::fastNormalizeVec3(Vec3 *v) {
    auto x = v->x;
    auto y = v->y;
    auto z = v->z;
    auto s = x * x + y * y + z * z;
    auto r = inverseSquareRoot(s);
    x *= r;
    y *= r;
    z *= r;
    v->x = x;
    v->y = y;
    v->z = z;
}

void psyqo::SoftMath::project(const Vec3 *v, FixedPoint<> h, Vec2 *out) {
    auto x = v->x;
    auto y = v->y;
    auto z = v->z;
    auto r = h / z;
    x *= r;
    y *= r;
    out->x = x;
    out->y = y;
}
