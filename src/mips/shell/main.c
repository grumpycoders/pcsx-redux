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

// first 8 = cube
// last 8 = hull
static struct Vertex2D v[16];

#define ONE 16777216

static int s_hull = 0;
static int s_hullFrame = 0;

static unsigned s_frameCounter = 60 * 4;

static void render() {
    unsigned counter = s_frameCounter++ - 4 * 60;
    if (counter >= (4 * 60)) s_frameCounter = 4 * 60;
    int activateHull = counter == 60;
    if (counter >= 60) counter = 60;
    struct Matrix2D m;
    uint32_t t = DC_2PI - lerpU(0, DC_PI2 + DC_PI4, counter * 256 / 60);
    int32_t s = lerpD(1.5 * ONE, 0.75 * ONE, counter * ONE / 60);
    rotationMatrix2D(&m, t);
    scaleMatrix2D(&m, s);
    static const int32_t e = ONE;
    struct Vertex2D v1 = {.x = e, .y = e};
    struct Vertex2D v2 = {.x = -e, .y = e};
    struct Vertex2D v3 = {.x = e, .y = -e};
    struct Vertex2D v4 = {.x = -e, .y = -e};
    matrixVertexMul2D(&m, &v1);
    matrixVertexMul2D(&m, &v2);
    matrixVertexMul2D(&m, &v3);
    matrixVertexMul2D(&m, &v4);
    int hull = s_hull;
    if (hull) {
        counter = s_hullFrame++;
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
        m.vs[0].x = ONE;
        m.vs[0].y = 0;
        m.vs[1].x = 0;
        m.vs[1].y = ONE;
        scaleMatrix2D(&m, s);
        struct Vertex2D ve[8];
        for (int i = 0; i < hull; i++) {
            ve[i] = v[i + 8];
            matrixVertexMul2D(&m, &ve[i]);
            sendGPUVertex(&ve[i]);
        }
        sendGPUVertex(&ve[0]);
        GPU_DATA = 0x50005000;
        if (counter >= 40) {
            s_hull = 0;
        }
    }
    if (activateHull) {
        s_hullFrame = 0;
        v[0] = v1;
        v[1] = v2;
        v[2] = v3;
        v[3] = v4;
        s_hull = convexHull(v, 4);
    }

    struct GPUPolygonCommand cmd = {
        .shading = S_FLAT,
        .verticesCount = VC_4,
        .textured = TEX_OFF,
        .transparency = TRANS_OFF,
        .blending = BLEND_OFF,
        .color = s_saturated,
    };
    startPolygonCommand(&cmd);
    sendGPUVertex(&v1);
    sendGPUVertex(&v2);
    sendGPUVertex(&v3);
    sendGPUVertex(&v4);
}

int main() {
    generateTables();
    initGPU();
    enableDisplay();
    while (1) {
        waitVSync();
        flip();
        render();
    }
}
