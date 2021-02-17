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
#include "common/syscalls/syscalls.h"
#include "shell/cdrom.h"
#include "shell/dcos.h"
#include "shell/gpu.h"
#include "shell/hull.h"
#include "shell/math.h"
#include "shell/spu.h"

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

static const struct Vertex3D c_modelVertices[8] = {
    {ONE, ONE, ONE},  {-ONE, ONE, ONE},  {-ONE, -ONE, ONE},  {ONE, -ONE, ONE},
    {ONE, ONE, -ONE}, {-ONE, ONE, -ONE}, {-ONE, -ONE, -ONE}, {ONE, -ONE, -ONE},
};
static const unsigned c_modelQuads[6][4] = {
    {0, 1, 2, 3}, {0, 4, 5, 1}, {0, 3, 7, 4}, {4, 7, 6, 5}, {2, 6, 7, 3}, {1, 5, 6, 2},
};

#define NL ONE
static const struct Vertex3D c_modelNormals[6] = {
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

static unsigned s_FPS = 0;
static int32_t s_quarterSecLerpSpeed = 0;

static const int32_t c_xRotSpeedIdle = 3 * ONE / (2 * DC_2PI);
static const int32_t c_yRotSpeedIdle = 4 * ONE / (3 * DC_2PI);
static const int32_t c_zRotSpeedIdle = ONE / DC_2PI;

static const int32_t c_xRotSpeedError = 0;
static const int32_t c_yRotSpeedError = ONE / (DC_2PI * 3);
static const int32_t c_zRotSpeedError = 0;

static const union Color c_black = {.r = 0, .g = 0, .b = 0};
static const union Color c_white = {.r = 255, .g = 255, .b = 255};
static const union Color c_bgIdle = {.r = 0, .g = 64, .b = 91};
static const union Color c_fgIdle = {.r = 156, .g = 220, .b = 218};
static const union Color c_bgError = {.r = 60, .g = 18, .b = 0};
static const union Color c_fgError = {.r = 220, .g = 156, .b = 156};
static const union Color c_bgSuccess = {.r = 36, .g = 91, .b = 0};
static const union Color c_fgSuccess = {.r = 152, .g = 224, .b = 155};

static union Color s_bg;
static union Color s_fg;
static union Color s_black;

static int32_t s_xRotSpeed = c_xRotSpeedIdle;
static int32_t s_yRotSpeed = c_yRotSpeedIdle;
static int32_t s_zRotSpeed = c_zRotSpeedIdle;

static int32_t s_xRotAccel = 0;
static int32_t s_yRotAccel = 0;
static int32_t s_zRotAccel = 0;

static int32_t s_xRot = 0;
static int32_t s_yRot = 0;
static int32_t s_zRot = ONE / 8;

static int32_t s_scale = ONE;

struct LerpU {
    uint32_t s;
    uint32_t d;
    uint32_t *const r;
};
struct LerpS {
    int32_t s;
    int32_t d;
    int32_t *const r;
};
struct LerpD {
    int32_t s;
    int32_t d;
    int32_t *const r;
};
struct LerpC {
    union Color s;
    union Color d;
    union Color *const r;
};
struct Lerp {
    union {
        struct LerpU u;
        struct LerpS s;
        struct LerpD d;
        struct LerpC c;
    };
    int32_t p;
    int32_t speed;
    enum {
        LERPU,
        LERPS,
        LERPD,
        LERPC,
    } type;
};

enum LerpID {
    LERP_TO_IDLE,
    LERP_TO_SUCCESS,
    LERP_TO_ERROR,
    LERP_TO_OUTRO,
    LERP_TO_BLACK,
};

static struct Lerp s_lerps[] = {
    {0, 0, (uint32_t *)&s_bg, 0, 0, LERPC},
    {0, 0, (uint32_t *)&s_fg, 0, 0, LERPC},
    {0, 0, (uint32_t *)&s_black, 0, 0, LERPC},
    {0, 0, (uint32_t *)&s_xRotSpeed, 0, 0, LERPD},
    {0, 0, (uint32_t *)&s_yRotSpeed, 0, 0, LERPD},
    {0, 0, (uint32_t *)&s_zRotSpeed, 0, 0, LERPD},
    {ONE, ONE >> 3, (uint32_t *)&s_scale, 0, 0, LERPD},
};

static void applyLerps() {
    const unsigned n = sizeof(s_lerps) / sizeof(s_lerps[0]);

    for (unsigned i = 0; i < n; i++) {
        if (s_lerps[i].speed == 0) continue;
        int32_t p = s_lerps[i].p;
        if (p >= ONE) s_lerps[i].speed = 0;
        switch (s_lerps[i].type) {
            case LERPU:
                *s_lerps[i].u.r = lerpU(s_lerps[i].u.s, s_lerps[i].u.d, p >> 16);
                break;
            case LERPS:
                *s_lerps[i].s.r = lerpS(s_lerps[i].s.s, s_lerps[i].s.d, p >> 16);
                break;
            case LERPD:
                *s_lerps[i].d.r = lerpD(s_lerps[i].d.s, s_lerps[i].d.d, p);
                break;
            case LERPC:
                *s_lerps[i].c.r = lerpC(s_lerps[i].c.s, s_lerps[i].c.d, p >> 16);
                break;
        }
        p += s_lerps[i].speed;
        if (p > ONE) p = ONE;
        s_lerps[i].p = p;
    }
}

static void startLerp(enum LerpID lerpID) {
    s_lerps[0].p = s_lerps[1].p = s_lerps[2].p = s_lerps[3].p = s_lerps[4].p = s_lerps[5].p = 0;
    s_lerps[0].speed = s_lerps[1].speed = s_lerps[3].speed = s_lerps[4].speed = s_lerps[5].speed = s_quarterSecLerpSpeed;
    s_lerps[0].c.s = *s_lerps[0].c.r;
    s_lerps[1].c.s = *s_lerps[1].c.r;
    s_lerps[2].c.s = *s_lerps[2].c.r;
    s_lerps[3].d.s = *s_lerps[3].d.r;
    s_lerps[4].d.s = *s_lerps[4].d.r;
    s_lerps[5].d.s = *s_lerps[5].d.r;
    switch (lerpID) {
        case LERP_TO_IDLE:
            s_lerps[0].c.d = c_bgIdle;
            s_lerps[1].c.d = c_fgIdle;
            s_lerps[3].d.d = c_xRotSpeedIdle;
            s_lerps[4].d.d = c_yRotSpeedIdle;
            s_lerps[5].d.d = c_zRotSpeedIdle;
            break;
        case LERP_TO_SUCCESS:
            s_lerps[0].c.d = c_bgSuccess;
            s_lerps[1].c.d = c_fgSuccess;
            s_lerps[3].d.d = c_xRotSpeedIdle;
            s_lerps[4].d.d = c_yRotSpeedIdle;
            s_lerps[5].d.d = c_zRotSpeedIdle;
            break;
        case LERP_TO_ERROR:
            s_lerps[0].c.d = c_bgError;
            s_lerps[1].c.d = c_fgError;
            s_lerps[3].d.d = c_xRotSpeedError;
            s_lerps[4].d.d = c_yRotSpeedError;
            s_lerps[5].d.d = c_zRotSpeedError;
            break;
        case LERP_TO_OUTRO:
            s_lerps[0].c.d = c_white;
            s_lerps[1].c.d = c_white;
            s_lerps[2].c.d = c_white;
            s_lerps[0].speed = s_lerps[1].speed = s_lerps[2].speed = s_lerps[6].speed = s_quarterSecLerpSpeed >> 2;
            s_lerps[3].speed = s_lerps[4].speed = s_lerps[5].speed = 0;
            break;
        case LERP_TO_BLACK:
            s_lerps[0].c.d = c_black;
            s_lerps[1].c.d = c_black;
            s_lerps[2].c.d = c_black;
            s_lerps[0].speed = s_lerps[1].speed = s_lerps[2].speed = s_quarterSecLerpSpeed >> 2;
            break;
    }
}

static void calculateFrame() {
    unsigned counter = s_frameCounter++;
    if (counter == s_FPS) s_phase = 1;
    int phase = s_phase;
    if ((counter + 4 * s_FPS) % (5 * s_FPS) == 1) {
        s_hullFrame = 0;
        s_hull = convexHull(v, 8);
    }
    struct Matrix3D transform;
    if (phase == 0) {
        uint32_t angle = DC_2PI - lerpU(0, DC_PI2 + DC_PI4, counter * 256 / s_FPS);
        int32_t scale = lerpD(1.58 * ONE, ONE, counter * ONE / s_FPS);
        generateRotationMatrix3D(&transform, angle, AXIS_Z);
        scaleMatrix3D(&transform, scale);
    } else {
        unsigned t = counter - s_FPS;
        generateRotationMatrix3D(&transform, s_zRot >> 13, AXIS_Z);
        struct Matrix3D rot;
        generateRotationMatrix3D(&rot, s_xRot >> 13, AXIS_X);
        multiplyMatrix3D(&transform, &rot, &transform);
        generateRotationMatrix3D(&rot, s_yRot >> 13, AXIS_Y);
        multiplyMatrix3D(&transform, &rot, &transform);
        scaleMatrix3D(&transform, s_scale);
        s_xRot += s_xRotSpeed;
        s_yRot += s_yRotSpeed;
        s_zRot += s_zRotSpeed;
        s_xRotSpeed += s_xRotAccel;
        s_yRotSpeed += s_yRotAccel;
        s_zRotSpeed += s_zRotAccel;
        while (s_xRot >= ONE) s_xRot -= ONE;
        while (s_yRot >= ONE) s_yRot -= ONE;
        while (s_zRot >= ONE) s_zRot -= ONE;
        while (s_xRot < 0) s_xRot += ONE;
        while (s_yRot < 0) s_yRot += ONE;
        while (s_zRot < 0) s_zRot += ONE;
    }

    for (unsigned i = 0; i < 8; i++) {
        struct Vertex3D out;
        matrixVertexMul3D(&transform, &c_modelVertices[i], &out);
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
            n[i] = matrixVertexMul3Dz(&transform, &c_modelNormals[i]);
        }
    }
}

static void facesSort(unsigned *faces, int count) {
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
        unsigned p = counter * 256 * 3 / (2 * s_FPS);
        union Color c = lerpC(s_fg, s_bg, p);
        struct GPULineCommand cmd = {
            .shading = S_FLAT,
            .lineStyle = POLY_ON,
            .transparency = TRANS_OFF,
            .color = c,
        };
        startLineCommand(&cmd);
        int32_t s = lerpD(ONE, 1.75 * ONE, counter * ONE * 3 / (2 * s_FPS));
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
        unsigned f = faces[i];
        unsigned p = n[f] >> 16;
        union Color c = lerpC(s_black, s_fg, p);
        struct GPUPolygonCommand cmd = {
            .shading = S_FLAT,
            .verticesCount = VC_4,
            .textured = TEX_OFF,
            .transparency = TRANS_OFF,
            .blending = BLEND_OFF,
            .color = c,
        };
        startPolygonCommand(&cmd);
        sendGPUVertex(&v[c_modelQuads[f][0]]);
        sendGPUVertex(&v[c_modelQuads[f][1]]);
        sendGPUVertex(&v[c_modelQuads[f][2]]);
        sendGPUVertex(&v[c_modelQuads[f][3]]);
    }
}

static int s_scheduleBoot = 0;
static int s_bootFrames = 0;

int main() {
    int wasLocked = enterCriticalSection();
    int isPAL = (*((char *)0xbfc7ff52) == 'E');
    s_FPS = isPAL ? 50 : 60;
    generateTables();
    s_quarterSecLerpSpeed = 4 * ONE / s_FPS;
    s_bg = s_fg = s_black = c_black;
    startLerp(LERP_TO_IDLE);
    initGPU(isPAL);
    initSPU();
    initCD();
    enableDisplay();
    while (1) {
        if (s_scheduleBoot && s_phase != 0) {
            int bootFrames = s_bootFrames++;
            if (bootFrames == 0) {
                startLerp(LERP_TO_SUCCESS);
                s_xRotAccel = s_yRotAccel = s_zRotAccel = 6000;
            } else if (bootFrames == s_FPS) {
                startLerp(LERP_TO_OUTRO);
            } else if (bootFrames == (s_FPS * 2)) {
                startLerp(LERP_TO_BLACK);
            } else if (bootFrames == (s_FPS * 3)) {
                break;
            }
        }
        applyLerps();
        calculateFrame();
        int wasError = isCDError();
        int wasSuccess = isCDSuccess();
        checkCD(s_FPS);
        int isError = isCDError();
        int isSuccess = isCDSuccess();
        if (isError && !wasError) {
            startLerp(LERP_TO_ERROR);
        } else if (isSuccess && !wasSuccess) {
            if (!isCDAudio()) {
                ramsyscall_printf("*** Data is acceptable, booting now. ***");
                s_scheduleBoot = 1;
            } else {
                // todo: play audio cd
            }
        } else if (!isError && wasError) {
            startLerp(LERP_TO_IDLE);
        }
        waitVSync(checkSPU);
        flip(0, s_bg);
        render();
    }
    if (!wasLocked) leaveCriticalSection();
}
