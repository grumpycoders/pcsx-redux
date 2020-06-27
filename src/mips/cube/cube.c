#include <stdlib.h>
#include <libetc.h>
#include <libgte.h>
#include <libgpu.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

#define OTSIZE 4096
#define SCREEN_Z 512
#define CUBESIZE 196

typedef struct DB {
    DRAWENV draw;
    DISPENV disp;
    u_long ot[OTSIZE];
    POLY_F4 s[6];
} DB;

static SVECTOR cube_vertices[] = {
    {-CUBESIZE / 2, -CUBESIZE / 2, -CUBESIZE / 2, 0}, {CUBESIZE / 2, -CUBESIZE / 2, -CUBESIZE / 2, 0},
    {CUBESIZE / 2, CUBESIZE / 2, -CUBESIZE / 2, 0},   {-CUBESIZE / 2, CUBESIZE / 2, -CUBESIZE / 2, 0},
    {-CUBESIZE / 2, -CUBESIZE / 2, CUBESIZE / 2, 0},  {CUBESIZE / 2, -CUBESIZE / 2, CUBESIZE / 2, 0},
    {CUBESIZE / 2, CUBESIZE / 2, CUBESIZE / 2, 0},    {-CUBESIZE / 2, CUBESIZE / 2, CUBESIZE / 2, 0},
};

static int cube_indices[] = {
    0, 1, 2, 3, 1, 5, 6, 2, 5, 4, 7, 6, 4, 0, 3, 7, 4, 5, 1, 0, 6, 7, 3, 2,
};

static void init_cube(DB *db, CVECTOR *col) {
    size_t i;

    for (i = 0; i < ARRAY_SIZE(db->s); ++i) {
        SetPolyF4(&db->s[i]);
        setRGB0(&db->s[i], col[i].r, col[i].g, col[i].b);
    }
}

static void add_cube(u_long *ot, POLY_F4 *s, MATRIX *transform) {
    long p, otz, flg;
    int nclip;
    size_t i;

    SetRotMatrix(transform);
    SetTransMatrix(transform);

    for (i = 0; i < ARRAY_SIZE(cube_indices); i += 4, ++s) {
        nclip = RotAverageNclip4(&cube_vertices[cube_indices[i + 0]], &cube_vertices[cube_indices[i + 1]],
                                 &cube_vertices[cube_indices[i + 2]], &cube_vertices[cube_indices[i + 3]],
                                 (long *)&s->x0, (long *)&s->x1, (long *)&s->x3, (long *)&s->x2, &p, &otz, &flg);

        if (nclip <= 0) continue;

        if ((otz > 0) && (otz < OTSIZE)) AddPrim(&ot[otz], s);
    }
}

int main(void) {
    DB db[2];
    DB *cdb;
    SVECTOR rotation = {0};
    VECTOR translation = {0, 0, (SCREEN_Z * 3) / 2, 0};
    MATRIX transform;
    CVECTOR col[6];
    size_t i;

    ResetGraph(0);
    InitGeom();

    SetGraphDebug(0);

    FntLoad(960, 256);
    SetDumpFnt(FntOpen(32, 32, 320, 64, 0, 512));

    SetGeomOffset(320, 240);
    SetGeomScreen(SCREEN_Z);

    SetDefDrawEnv(&db[0].draw, 0, 0, 640, 480);
    SetDefDrawEnv(&db[1].draw, 0, 0, 640, 480);
    SetDefDispEnv(&db[0].disp, 0, 0, 640, 480);
    SetDefDispEnv(&db[1].disp, 0, 0, 640, 480);

    srand(0);

    for (i = 0; i < ARRAY_SIZE(col); ++i) {
        col[i].r = rand();
        col[i].g = rand();
        col[i].b = rand();
    }

    init_cube(&db[0], col);
    init_cube(&db[1], col);

    SetDispMask(1);

    PutDrawEnv(&db[0].draw);
    PutDispEnv(&db[0].disp);

    while (1) {
        cdb = (cdb == &db[0]) ? &db[1] : &db[0];

        rotation.vy += 16;
        rotation.vz += 16;

        RotMatrix(&rotation, &transform);
        TransMatrix(&transform, &translation);

        ClearOTagR(cdb->ot, OTSIZE);

        FntPrint("Cube example compiled using psyq libraries,\n");
        FntPrint("converted by psyq-obj-parser, \n");
        FntPrint("PCSX-Redux project,\n");
        FntPrint("https://github.com/grumpycoders/pcsx-redux\n");

        add_cube(cdb->ot, cdb->s, &transform);

        DrawSync(0);
        VSync(0);

        ClearImage(&cdb->draw.clip, 60, 120, 120);

        DrawOTag(&cdb->ot[OTSIZE - 1]);
        FntFlush(-1);
    }

    return 0;
}
