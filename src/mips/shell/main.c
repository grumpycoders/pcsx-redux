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

#include "common/hardware/hwregs.h"
#include "shell/dcos.h"
#include "shell/gpu.h"
#include "shell/hull.h"
#include "shell/math.h"

static void generateTables() { generateCosTable(); }

/*
clang-format off
          x
    *------>
   /|
 z/ |      6--------7
 L  |y    /|       /|
    V    2--------3 |
         | |      | |
         | 5------|-4
         |/       |/
         1--------0

clang-format on
*/

static const struct Vertex3D modelVertices[8] = {
    {ONE, ONE, ONE},  {-ONE, ONE, ONE},  {-ONE, -ONE, ONE},  {ONE, -ONE, ONE},
    {ONE, ONE, -ONE}, {-ONE, ONE, -ONE}, {-ONE, -ONE, -ONE}, {ONE, -ONE, -ONE},
};
static const unsigned modelQuads[6][4] = {
    {0, 1, 2, 3}, {0, 4, 5, 1}, {0, 3, 7, 4}, {4, 7, 6, 5}, {2, 6, 7, 3}, {1, 5, 6, 2},
};

#define NL 22369621
static const struct Vertex3D modelNormals[6] = {
    {0, 0, NL}, {0, NL, 0}, {NL, 0, 0}, {0, 0, -NL}, {0, -NL, 0}, {-NL, 0, 0},
};

// first 8 = cube
// last 8 = hull
static struct Vertex2D v[16];
static int32_t n[6];

static int s_hull = 0;
static int s_hullFrame = 0;

static const int32_t F = ONE * 12;

static unsigned s_frameCounter = 0;
static int s_phase = 0;

static void calculateFrame() {
    unsigned counter = s_frameCounter++;
    if (counter == 60) s_phase = 1;
    int phase = s_phase;
    if ((counter + 4 * 60) % (5 * 60) == 1) {
        s_hullFrame = 0;
        s_hull = convexHull(v, 8);
    }
    struct Matrix3D transform;
    if (phase == 0) {
        uint32_t t = DC_2PI - lerpU(0, DC_PI2 + DC_PI4, counter * 256 / 60);
        int32_t s = lerpD(1.28 * ONE, 0.75 * ONE, counter * ONE / 60);
        generateRotationMatrix3D(&transform, t, AXIS_Z);
        scaleMatrix3D(&transform, s);
    } else {
        unsigned t = counter - 60;
        generateRotationMatrix3D(&transform, t + DC_PI4, AXIS_Z);
        struct Matrix3D rot;
        generateRotationMatrix3D(&rot, t * 3 / 2, AXIS_X);
        multiplyMatrix3D(&transform, &rot, &transform);
        generateRotationMatrix3D(&rot, t * 4 / 3, AXIS_Y);
        multiplyMatrix3D(&transform, &rot, &transform);
        scaleMatrix3D(&transform, 0.75 * ONE);
    }

    for (unsigned i = 0; i < 8; i++) {
        struct Vertex3D out;
        matrixVertexMul3D(&transform, &modelVertices[i], &out);
        if (phase == 0) {
            v[i].x = out.x;
            v[i].y = out.y;
        } else {
            int32_t d = dDiv(F, F + ONE - out.z);
            v[i].x = dMul(out.x, d);
            v[i].y = dMul(out.y, d);
        }
    }
    if (phase == 0) {
        n[0] = ONE;
        for (unsigned i = 1; i < 6; i++) {
            n[i] = -ONE;
        }
    } else {
        for (unsigned i = 0; i < 6; i++) {
            n[i] = matrixVertexMul3Dz(&transform, &modelNormals[i]);
        }
    }
}

static void facesSort(unsigned* faces, int count) {
    int i, j;
    for (i = 0; i < count - 1; i++) {
        for (j = 0; j < count - i - 1; j++) {
            if (n[faces[j]] > n[faces[j + 1]]) {
                int t = faces[j];
                faces[j] = faces[j + 1];
                faces[j + 1] = t;
            }
        }
    }
}

static void render() {
    int hull = s_hull;
    if (hull) {
        unsigned counter = s_hullFrame++;
        union Color c;
        unsigned p = counter * 256 / 40;
        c.r = lerpU(s_saturated.r, s_bg.r, p);
        c.g = lerpU(s_saturated.g, s_bg.g, p);
        c.b = lerpU(s_saturated.b, s_bg.b, p);
        struct GPULineCommand cmd = {
            .shading = S_FLAT,
            .lineStyle = POLY_ON,
            .transparency = TRANS_OFF,
            .color = c,
        };
        startLineCommand(&cmd);
        int32_t s = lerpD(ONE, 1.75 * ONE, counter * ONE / 40);
        struct Matrix2D m;
        m.vs[0].x = s;
        m.vs[0].y = 0;
        m.vs[1].x = 0;
        m.vs[1].y = s;
        struct Vertex2D ve[8];
        for (int i = 0; i < hull; i++) {
            ve[i] = v[i + 8];
            matrixVertexMul2D(&m, &ve[i]);
            sendGPUVertex(&ve[i]);
        }
        sendGPUVertex(&ve[0]);
        GPU_DATA = 0x50005000;
        if (counter >= 40) s_hull = 0;
    }

    unsigned faces[6];
    unsigned count = 0;

    for (unsigned i = 0; i < 6; i++) {
        if (n[i] <= 0) continue;
        faces[count++] = i;
    }
    facesSort(faces, count);
    for (unsigned i = 0; i < count; i++) {
        union Color c;
        unsigned f = faces[i];
        unsigned p = n[f] >> 16;
        c.r = lerpU(0, s_saturated.r, p);
        c.g = lerpU(0, s_saturated.g, p);
        c.b = lerpU(0, s_saturated.b, p);
        struct GPUPolygonCommand cmd = {
            .shading = S_FLAT,
            .verticesCount = VC_4,
            .textured = TEX_OFF,
            .transparency = TRANS_OFF,
            .blending = BLEND_OFF,
            .color = c,
        };
        startPolygonCommand(&cmd);
        sendGPUVertex(&v[modelQuads[f][0]]);
        sendGPUVertex(&v[modelQuads[f][1]]);
        sendGPUVertex(&v[modelQuads[f][2]]);
        sendGPUVertex(&v[modelQuads[f][3]]);
    }
}

void idle() {}

int main() {
    generateTables();
    initGPU();
    enableDisplay();
    while (1) {
        calculateFrame();
        idle();
        waitVSync();
        flip();
        render();
    }
}
