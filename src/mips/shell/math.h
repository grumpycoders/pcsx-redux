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

#include <stdint.h>

#include "shell/dcos.h"

#define ONE 16777216

static inline int32_t dMul(int32_t a, int32_t b) {
    long long r = a;
    r *= b;
    return r >> 24;
}
int32_t dDiv(int32_t a, int32_t b);

struct Vertex2D {
    int32_t x, y;
};

struct Matrix2D {
    struct Vertex2D vs[2];
};

struct Vertex3D {
    int32_t x, y, z;
};

struct Matrix3D {
    struct Vertex3D vs[3];
};

enum Axis { AXIS_X, AXIS_Y, AXIS_Z };

void generateRotationMatrix3D(struct Matrix3D *m, int t, enum Axis a);
void multiplyMatrix3D(const struct Matrix3D *m1, const struct Matrix3D *m2, struct Matrix3D *out);
void scaleMatrix3D(struct Matrix3D *m, int32_t s);
void matrixVertexMul3D(const struct Matrix3D *m, const struct Vertex3D *v, struct Vertex3D *out);
void matrixVertexMul3Dxy(const struct Matrix3D *m, const struct Vertex3D *v, struct Vertex2D *out);
int32_t matrixVertexMul3Dz(const struct Matrix3D *m, const struct Vertex3D *v);

static inline void rotationMatrix2D(struct Matrix2D *m, int t) {
    int32_t c = dCos(t);
    int32_t s = dSin(t);
    m->vs[0].x = c;
    m->vs[0].y = s;
    m->vs[1].x = -s;
    m->vs[1].y = c;
}

static inline void scaleMatrix2D(struct Matrix2D *m, int32_t s) {
    m->vs[0].x = dMul(m->vs[0].x, s);
    m->vs[0].y = dMul(m->vs[0].y, s);
    m->vs[1].x = dMul(m->vs[1].x, s);
    m->vs[1].y = dMul(m->vs[1].y, s);
}

static inline void matrixVertexMul2D(struct Matrix2D *m, struct Vertex2D *v) {
    int32_t x = v->x;
    int32_t y = v->y;
    int32_t mx1 = m->vs[0].x;
    int32_t my1 = m->vs[0].y;
    int32_t mx2 = m->vs[1].x;
    int32_t my2 = m->vs[1].y;
    int32_t nx1 = dMul(x, mx1);
    int32_t ny1 = dMul(y, my1);
    int32_t nx2 = dMul(x, mx2);
    int32_t ny2 = dMul(y, my2);
    int32_t nx = nx1 + ny1;
    int32_t ny = nx2 + ny2;
    v->x = nx;
    v->y = ny;
}

// standard lerp function
//  s = source, an arbitrary number up to 2^24
//  d = destination, an arbitrary number up to 2^24
//  p = position, a number between 0 and 256, inclusive
//  p = 0 means output = s
//  p = 256 means output = d
static inline uint32_t lerpU(uint32_t s, uint32_t d, unsigned p) { return (s * (256 - p) + d * p) >> 8; }
static inline int32_t lerpS(int32_t s, int32_t d, unsigned p) { return (s * (256 - p) + d * p) >> 8; }
static inline int32_t lerpD(int32_t s, int32_t d, int32_t p) { return dMul(s, 16777216 - p) + dMul(d, p); }
