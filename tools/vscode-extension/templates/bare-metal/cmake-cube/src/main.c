/*
 * This program is a simple demo that displays a 3D cube and some text (using
 * the font spritesheet in the assets directory), based on the following
 * examples:
 *     https://github.com/spicyjpeg/ps1-bare-metal/blob/main/src/06_fonts/main.c
 *     https://github.com/spicyjpeg/ps1-bare-metal/blob/main/src/08_spinningCube/main.c
 *
 * For further information on the contents of the ps1-bare-metal submodule, see:
 *     https://github.com/spicyjpeg/ps1-bare-metal
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include "font.h"
#include "gpu.h"
#include "ps1/cop0.h"
#include "ps1/gpucmd.h"
#include "ps1/gte.h"
#include "ps1/registers.h"
#include "trig.h"

// The GTE uses a 20.12 fixed-point format for most values. What this means is
// that fractional values will be stored as integers by multiplying them by a
// fixed unit, in this case 4096 or 1 << 12 (hence making the fractional part 12
// bits long). We'll define this unit value to make their handling easier.
#define ONE (1 << 12)

static void setupGTE(int width, int height) {
    // Ensure the GTE, which is coprocessor 2, is enabled. MIPS coprocessors are
    // enabled through the status register in coprocessor 0, which is always
    // accessible.
    cop0_setReg(COP0_SR, cop0_getReg(COP0_SR) | COP0_SR_CU2);

    // Set the offset to be added to all calculated screen space coordinates (we
    // want our cube to appear at the center of the screen) Note that OFX and
    // OFY are 16.16 fixed-point rather than 20.12.
    gte_setControlReg(GTE_OFX, (width  << 16) / 2);
    gte_setControlReg(GTE_OFY, (height << 16) / 2);

    // Set the distance of the perspective projection plane (i.e. the camera's
    // focal length), which affects the field of view.
    int focalLength = (width < height) ? width : height;

    gte_setControlReg(GTE_H, focalLength / 2);

    // Set the scaling factor for Z averaging. For each polygon drawn, the GTE
    // will sum the transformed Z coordinates of its vertices multiplied by this
    // value in order to derive the ordering table bucket index the polygon will
    // be sorted into. This will work best if the ordering table length is a
    // multiple of 12 (i.e. both 3 and 4) or high enough to make any rounding
    // error negligible.
    gte_setControlReg(GTE_ZSF3, ORDERING_TABLE_SIZE / 3);
    gte_setControlReg(GTE_ZSF4, ORDERING_TABLE_SIZE / 4);
}

// When transforming vertices, the GTE will multiply their vectors by a 3x3
// matrix stored in its registers. This matrix can be used, among other things,
// to rotate the model by multiplying it by the appropriate rotation matrices.
// The two functions below handle manipulation of this matrix.
static void multiplyCurrentMatrixByVectors(GTEMatrix *output) {
    // Multiply the GTE's current matrix by the matrix whose column vectors are
    // V0/V1/V2, then store the result to the provided location. This has to be
    // done one column at a time, as the GTE only supports multiplying a matrix
    // by a vector using the MVMVA command.
    gte_command(GTE_CMD_MVMVA | GTE_SF | GTE_MX_RT | GTE_V_V0 | GTE_CV_NONE);
    output->values[0][0] = gte_getDataReg(GTE_IR1);
    output->values[1][0] = gte_getDataReg(GTE_IR2);
    output->values[2][0] = gte_getDataReg(GTE_IR3);

    gte_command(GTE_CMD_MVMVA | GTE_SF | GTE_MX_RT | GTE_V_V1 | GTE_CV_NONE);
    output->values[0][1] = gte_getDataReg(GTE_IR1);
    output->values[1][1] = gte_getDataReg(GTE_IR2);
    output->values[2][1] = gte_getDataReg(GTE_IR3);

    gte_command(GTE_CMD_MVMVA | GTE_SF | GTE_MX_RT | GTE_V_V2 | GTE_CV_NONE);
    output->values[0][2] = gte_getDataReg(GTE_IR1);
    output->values[1][2] = gte_getDataReg(GTE_IR2);
    output->values[2][2] = gte_getDataReg(GTE_IR3);
}

static void rotateCurrentMatrix(int yaw, int pitch, int roll) {
    static GTEMatrix multiplied;
    int              s, c;

    // For each axis, compute the rotation matrix then "combine" it with the
    // GTE's current matrix by multiplying the two and writing the result back
    // to the GTE's registers.
    if (yaw) {
        s = isin(yaw);
        c = icos(yaw);

        gte_setColumnVectors(
            c, -s,   0,
            s,  c,   0,
            0,  0, ONE
        );
        multiplyCurrentMatrixByVectors(&multiplied);
        gte_loadRotationMatrix(&multiplied);
    }
    if (pitch) {
        s = isin(pitch);
        c = icos(pitch);

        gte_setColumnVectors(
             c,   0, s,
             0, ONE, 0,
            -s,   0, c
        );
        multiplyCurrentMatrixByVectors(&multiplied);
        gte_loadRotationMatrix(&multiplied);
    }
    if (roll) {
        s = isin(roll);
        c = icos(roll);

        gte_setColumnVectors(
            ONE, 0,  0,
              0, c, -s,
              0, s,  c
        );
        multiplyCurrentMatrixByVectors(&multiplied);
        gte_loadRotationMatrix(&multiplied);
    }
}

// We're going to store the 3D model of our cube as two separate arrays, one
// containing a list of unique vertices and the other referencing those vertices
// to build up quadrilateral faces. This approach of having a "palette" of
// vertices, in a similar way to how indexed color works, allows for significant
// memory savings as most if not all faces usually have vertices in common.
typedef struct {
    uint8_t  vertices[4];
    uint32_t color;
} Face;

#define NUM_CUBE_VERTICES 8
#define NUM_CUBE_FACES    6

static const GTEVector16 cubeVertices[NUM_CUBE_VERTICES] = {
    { .x = -32, .y = -32, .z = -32 },
    { .x =  32, .y = -32, .z = -32 },
    { .x = -32, .y =  32, .z = -32 },
    { .x =  32, .y =  32, .z = -32 },
    { .x = -32, .y = -32, .z =  32 },
    { .x =  32, .y = -32, .z =  32 },
    { .x = -32, .y =  32, .z =  32 },
    { .x =  32, .y =  32, .z =  32 }
};

// Note that there are several requirements on the order of vertices:
// - they must be arranged in a Z-like shape rather than clockwise or
//   counterclockwise, since the GPU processes a quad with vertices (A, B, C, D)
//   as two triangles with vertices (A, B, C) and (B, C, D) respectively;
// - the first 3 vertices must be ordered clockwise when the face is viewed from
//   the front, as the code relies on this to determine whether or not the quad
//   is facing the camera (see main()).
// For instance, only the first of these faces (viewed from the front) has its
// vertices ordered correctly:
//     0----1        0----1        2----3
//     |  / |        | \/ |        | \  |
//     | /  |        | /\ |        |  \ |
//     2----3        3----2        0----1
//     Correct    Not Z-shaped  Not clockwise
static const Face cubeFaces[NUM_CUBE_FACES] = {
    { .vertices = { 0, 1, 2, 3 }, .color = 0x0000ff },
    { .vertices = { 6, 7, 4, 5 }, .color = 0x00ff00 },
    { .vertices = { 4, 5, 0, 1 }, .color = 0x00ffff },
    { .vertices = { 7, 6, 3, 2 }, .color = 0xff0000 },
    { .vertices = { 6, 4, 2, 0 }, .color = 0xff00ff },
    { .vertices = { 5, 7, 1, 3 }, .color = 0xffff00 }
};

#define SCREEN_WIDTH     320
#define SCREEN_HEIGHT    240
#define FONT_WIDTH       96
#define FONT_HEIGHT      56
#define FONT_COLOR_DEPTH GP0_COLOR_4BPP

extern const uint8_t fontTexture[], fontPalette[];

int main(int argc, const char **argv) {
    initSerialIO(115200);

    if ((GPU_GP1 & GP1_STAT_FB_MODE_BITMASK) == GP1_STAT_FB_MODE_PAL) {
        puts("Using PAL mode");
        setupGPU(GP1_MODE_PAL, SCREEN_WIDTH, SCREEN_HEIGHT);
    } else {
        puts("Using NTSC mode");
        setupGPU(GP1_MODE_NTSC, SCREEN_WIDTH, SCREEN_HEIGHT);
    }

    setupGTE(SCREEN_WIDTH, SCREEN_HEIGHT);

    DMA_DPCR |= DMA_DPCR_ENABLE << (DMA_GPU * 4);
    DMA_DPCR |= DMA_DPCR_ENABLE << (DMA_OTC * 4);

    GPU_GP1 = gp1_dmaRequestMode(GP1_DREQ_GP0_WRITE);
    GPU_GP1 = gp1_dispBlank(false);

    // Upload the font texture to VRAM.
    TextureInfo font;

    uploadIndexedTexture(
        &font, fontTexture, fontPalette, SCREEN_WIDTH * 2, 0, SCREEN_WIDTH * 2,
        FONT_HEIGHT, FONT_WIDTH, FONT_HEIGHT, FONT_COLOR_DEPTH
    );

    DMAChain dmaChains[2];
    bool     usingSecondFrame = false;
    int      frameCounter     = 0;

    for (;;) {
        int bufferX = usingSecondFrame ? SCREEN_WIDTH : 0;
        int bufferY = 0;

        DMAChain *chain  = &dmaChains[usingSecondFrame];
        usingSecondFrame = !usingSecondFrame;

        uint32_t *ptr;

        GPU_GP1 = gp1_fbOffset(bufferX, bufferY);

        clearOrderingTable(chain->orderingTable, ORDERING_TABLE_SIZE);
        chain->nextPacket = chain->data;

        // Reset the GTE's translation vector (added to each vertex) and
        // transformation matrix, then modify the matrix to rotate the cube. The
        // translation vector is used here to move the cube away from the camera
        // so it can be seen.
        gte_setControlReg(GTE_TRX,   0);
        gte_setControlReg(GTE_TRY,   0);
        gte_setControlReg(GTE_TRZ, 128);
        gte_setRotationMatrix(
            ONE,   0,   0,
              0, ONE,   0,
              0,   0, ONE
        );

        rotateCurrentMatrix(0, frameCounter * 16, frameCounter * 12);
        frameCounter++;

        // Draw the cube one face at a time.
        for (int i = 0; i < NUM_CUBE_FACES; i++) {
            const Face *face = &cubeFaces[i];

            // Apply perspective projection to the first 3 vertices. The GTE can
            // only process up to 3 vertices at a time, so we'll transform the
            // last one separately.
            gte_loadV0(&cubeVertices[face->vertices[0]]);
            gte_loadV1(&cubeVertices[face->vertices[1]]);
            gte_loadV2(&cubeVertices[face->vertices[2]]);
            gte_command(GTE_CMD_RTPT | GTE_SF);

            // Determine the winding order of the vertices on screen. If they
            // are ordered clockwise then the face is visible, otherwise it can
            // be skipped as it is not facing the camera.
            gte_command(GTE_CMD_NCLIP);

            if (gte_getDataReg(GTE_MAC0) <= 0)
                continue;

            // Save the first transformed vertex (the GTE only keeps the X/Y
            // coordinates of the last 3 vertices processed and Z coordinates of
            // the last 4 vertices processed) and apply projection to the last
            // vertex.
            uint32_t xy0 = gte_getDataReg(GTE_SXY0);

            gte_loadV0(&cubeVertices[face->vertices[3]]);
            gte_command(GTE_CMD_RTPS | GTE_SF);

            // Calculate the average Z coordinate of all vertices and use it to
            // determine the ordering table bucket index for this face.
            gte_command(GTE_CMD_AVSZ4 | GTE_SF);
            int zIndex = gte_getDataReg(GTE_OTZ);

            if ((zIndex < 0) || (zIndex >= ORDERING_TABLE_SIZE))
                continue;

            // Create a new quad and give its vertices the X/Y coordinates
            // calculated by the GTE.
            ptr    = allocatePacket(chain, zIndex, 5);
            ptr[0] = face->color | gp0_shadedQuad(false, false, false);
            ptr[1] = xy0;
            gte_storeDataReg(GTE_SXY0, 2 * 4, ptr);
            gte_storeDataReg(GTE_SXY1, 3 * 4, ptr);
            gte_storeDataReg(GTE_SXY2, 4 * 4, ptr);
        }

        ptr    = allocatePacket(chain, ORDERING_TABLE_SIZE - 1, 3);
        ptr[0] = gp0_rgb(64, 64, 64) | gp0_vramFill();
        ptr[1] = gp0_xy(bufferX, bufferY);
        ptr[2] = gp0_xy(SCREEN_WIDTH, SCREEN_HEIGHT);

        ptr    = allocatePacket(chain, ORDERING_TABLE_SIZE - 1, 4);
        ptr[0] = gp0_texpage(0, true, false);
        ptr[1] = gp0_fbOffset1(bufferX, bufferY);
        ptr[2] = gp0_fbOffset2(
            bufferX + SCREEN_WIDTH - 1, bufferY + SCREEN_HEIGHT - 2
        );
        ptr[3] = gp0_fbOrigin(bufferX, bufferY);

        // Draw some text in front of the cube.
        printString(
            chain, &font, 16, 32, 0,
            "PSX.Dev bare-metal CMake example\n"
            "PCSX-Redux project\n"
            "https://bit.ly/pcsx-redux"
        );

        waitForGP0Ready();
        waitForVSync();
        sendLinkedList(&(chain->orderingTable)[ORDERING_TABLE_SIZE - 1]);
    }

    return 0;
}
