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

#include "shell/math.h"

#include <stdint.h>

#include "shell/dcos.h"

void generateRotationMatrix3D(struct Matrix3D *m, int t, enum Axis a) {
    int32_t s = dSin(t);
    int32_t c = dCos(t);
    switch (a) {
        case AXIS_X:
            m->vs[0].x = ONE;
            m->vs[0].y = 0;
            m->vs[0].z = 0;
            m->vs[1].x = 0;
            m->vs[1].y = c;
            m->vs[1].z = s;
            m->vs[2].x = 0;
            m->vs[2].y = -s;
            m->vs[2].z = c;
            break;
        case AXIS_Y:
            m->vs[0].x = c;
            m->vs[0].y = 0;
            m->vs[0].z = -s;
            m->vs[1].x = 0;
            m->vs[1].y = ONE;
            m->vs[1].z = 0;
            m->vs[2].x = s;
            m->vs[2].y = 0;
            m->vs[2].z = c;
            break;
        case AXIS_Z:
            m->vs[0].x = c;
            m->vs[0].y = s;
            m->vs[0].z = 0;
            m->vs[1].x = -s;
            m->vs[1].y = c;
            m->vs[1].z = 0;
            m->vs[2].x = 0;
            m->vs[2].y = 0;
            m->vs[2].z = ONE;
            break;
    }
}

void multiplyMatrix3D(const struct Matrix3D *m1, const struct Matrix3D *m2, struct Matrix3D *out) {
    int32_t x0 = dMul(m1->vs[0].x, m2->vs[0].x) + dMul(m1->vs[1].x, m2->vs[0].y) + dMul(m1->vs[2].x, m2->vs[0].z);
    int32_t y0 = dMul(m1->vs[0].y, m2->vs[0].x) + dMul(m1->vs[1].y, m2->vs[0].y) + dMul(m1->vs[2].y, m2->vs[0].z);
    int32_t z0 = dMul(m1->vs[0].z, m2->vs[0].x) + dMul(m1->vs[1].z, m2->vs[0].y) + dMul(m1->vs[2].z, m2->vs[0].z);
    int32_t x1 = dMul(m1->vs[0].x, m2->vs[1].x) + dMul(m1->vs[1].x, m2->vs[1].y) + dMul(m1->vs[2].x, m2->vs[1].z);
    int32_t y1 = dMul(m1->vs[0].y, m2->vs[1].x) + dMul(m1->vs[1].y, m2->vs[1].y) + dMul(m1->vs[2].y, m2->vs[1].z);
    int32_t z1 = dMul(m1->vs[0].z, m2->vs[1].x) + dMul(m1->vs[1].z, m2->vs[1].y) + dMul(m1->vs[2].z, m2->vs[1].z);
    int32_t x2 = dMul(m1->vs[0].x, m2->vs[2].x) + dMul(m1->vs[1].x, m2->vs[2].y) + dMul(m1->vs[2].x, m2->vs[2].z);
    int32_t y2 = dMul(m1->vs[0].y, m2->vs[2].x) + dMul(m1->vs[1].y, m2->vs[2].y) + dMul(m1->vs[2].y, m2->vs[2].z);
    int32_t z2 = dMul(m1->vs[0].z, m2->vs[2].x) + dMul(m1->vs[1].z, m2->vs[2].y) + dMul(m1->vs[2].z, m2->vs[2].z);

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

void scaleMatrix3D(struct Matrix3D *m, int32_t s) {
    m->vs[0].x = dMul(m->vs[0].x, s);
    m->vs[0].y = dMul(m->vs[0].y, s);
    m->vs[0].z = dMul(m->vs[0].z, s);
    m->vs[1].x = dMul(m->vs[1].x, s);
    m->vs[1].y = dMul(m->vs[1].y, s);
    m->vs[1].z = dMul(m->vs[1].z, s);
    m->vs[2].x = dMul(m->vs[2].x, s);
    m->vs[2].y = dMul(m->vs[2].y, s);
    m->vs[2].z = dMul(m->vs[2].z, s);
}

void matrixVertexMul3D(const struct Matrix3D *m, const struct Vertex3D *v, struct Vertex3D *out) {
    int32_t x = v->x;
    int32_t y = v->y;
    int32_t z = v->z;
    int32_t mx1 = m->vs[0].x;
    int32_t my1 = m->vs[0].y;
    int32_t mz1 = m->vs[0].z;
    int32_t mx2 = m->vs[1].x;
    int32_t my2 = m->vs[1].y;
    int32_t mz2 = m->vs[1].z;
    int32_t mx3 = m->vs[2].x;
    int32_t my3 = m->vs[2].y;
    int32_t mz3 = m->vs[2].z;
    int32_t nx1 = dMul(x, mx1);
    int32_t ny1 = dMul(y, my1);
    int32_t nz1 = dMul(z, mz1);
    int32_t nx2 = dMul(x, mx2);
    int32_t ny2 = dMul(y, my2);
    int32_t nz2 = dMul(z, mz2);
    int32_t nx3 = dMul(x, mx3);
    int32_t ny3 = dMul(y, my3);
    int32_t nz3 = dMul(z, mz3);
    int32_t nx = nx1 + ny1 + nz1;
    int32_t ny = nx2 + ny2 + nz2;
    int32_t nz = nx3 + ny3 + nz3;
    out->x = nx;
    out->y = ny;
    out->z = nz;
}

void matrixVertexMul3Dxy(const struct Matrix3D *m, const struct Vertex3D *v, struct Vertex2D *out) {
    int32_t x = v->x;
    int32_t y = v->y;
    int32_t z = v->z;
    int32_t mx1 = m->vs[0].x;
    int32_t my1 = m->vs[0].y;
    int32_t mz1 = m->vs[0].z;
    int32_t mx2 = m->vs[1].x;
    int32_t my2 = m->vs[1].y;
    int32_t mz2 = m->vs[1].z;
    int32_t nx1 = dMul(x, mx1);
    int32_t ny1 = dMul(y, my1);
    int32_t nz1 = dMul(z, mz1);
    int32_t nx2 = dMul(x, mx2);
    int32_t ny2 = dMul(y, my2);
    int32_t nz2 = dMul(z, mz2);
    int32_t nx = nx1 + ny1 + nz1;
    int32_t ny = nx2 + ny2 + nz2;
    out->x = nx;
    out->y = ny;
}

int32_t matrixVertexMul3Dz(const struct Matrix3D *m, const struct Vertex3D *v) {
    int32_t x = v->x;
    int32_t y = v->y;
    int32_t z = v->z;
    int32_t mx3 = m->vs[2].x;
    int32_t my3 = m->vs[2].y;
    int32_t mz3 = m->vs[2].z;
    int32_t nx3 = dMul(x, mx3);
    int32_t ny3 = dMul(y, my3);
    int32_t nz3 = dMul(z, mz3);
    return nx3 + ny3 + nz3;
}

static inline uint32_t iDiv(uint64_t rem, uint32_t base) {
    rem <<= 24;
    uint64_t b = base;
    uint64_t res, d = 1;
    uint32_t high = rem >> 32;

    res = 0;
    if (high >= base) {
        high /= base;
        res = (uint64_t)high << 32;
        rem -= (uint64_t)(high * base) << 32;
    }

    while ((int64_t)b > 0 && b < rem) {
        b = b + b;
        d = d + d;
    }

    do {
        if (rem >= b) {
            rem -= b;
            res += d;
        }
        b >>= 1;
        d >>= 1;
    } while (d);

    return res;
}

int32_t dDiv(int32_t a, int32_t b) {
    int s = 1;
    if (a < 0) {
        a = -a;
        s = -1;
    }
    if (b < 0) {
        b = -b;
        s = -s;
    }
    return iDiv(a, b) * s;
}
