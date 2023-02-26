'use strict'

const vscode = require('vscode')
const path = require('node:path')
const fs = require('fs-extra')
const { simpleGit } = require('simple-git')
const progressNotification = require('./progressnotification.js')

const stringify = (obj) => {
  return JSON.stringify(obj, null, 2)
}

async function createSkeleton(fullPath, name, progressReporter) {
  await fs.mkdirp(path.join(fullPath, '.vscode'))
  await fs.writeFile(
    path.join(fullPath, '.vscode', 'launch.json'),
    stringify({
      version: '0.2.0',
      configurations: [
        {
          name: 'Debug',
          type: 'gdb',
          request: 'attach',
          target: 'localhost:3333',
          remote: true,
          cwd: '${workspaceRoot}',
          valuesFormatting: 'parseText',
          executable: '${workspaceRoot}/${workspaceRootFolderName}.elf',
          stopAtConnect: true,
          gdbpath: 'gdb-multiarch',
          windows: {
            gdbpath: 'gdb.exe'
          },
          autorun: [
            'monitor reset shellhalt',
            'load ${workspaceRootFolderName}.elf',
            'tbreak main',
            'continue'
          ]
        }
      ]
    })
  )
  await fs.writeFile(
    path.join(fullPath, '.vscode', 'tasks.json'),
    stringify({
      version: '2.0.0',
      tasks: [
        {
          label: 'Build Debug',
          type: 'shell',
          command: 'make BUILD=Debug',
          group: {
            kind: 'build',
            isDefault: true
          },
          problemMatcher: ['$gcc']
        },
        {
          label: 'Build Release',
          type: 'shell',
          command: 'make',
          group: {
            kind: 'build',
            isDefault: true
          },
          problemMatcher: ['$gcc']
        },
        {
          label: 'Clean',
          type: 'shell',
          command: 'make clean',
          group: {
            kind: 'build'
          }
        }
      ]
    })
  )

  const git = simpleGit(fullPath)
  await git.init()
  await git.add('.vscode')
  await fs.mkdirp(path.join(fullPath, 'third_party'))
  progressReporter.report({ message: 'Adding submodules...' })
  await git.submoduleAdd(
    'https://github.com/pcsx-redux/nugget.git',
    'third_party/nugget'
  )

  await fs.writeFile(
    path.join(fullPath, '.gitignore'),
    `
*.elf
*.map
*.cpe
*.ps-exe
*.dep
*.o
*.a
PSX.Dev-README.md
third_party/psyq
`
  )

  await fs.writeFile(
    path.join(fullPath, 'PSX.Dev-README.md'),
    `
Welcome to your new PSX.Dev project!

In order to build your project, open the command palette (Ctrl+Shift+P) and run the "PSX.Dev: Build Debug" command. You can also use the "PSX.Dev: Build Release" command to build a release version of your project.
You can also use the "PSX.Dev: Clean" command to clean your project, which is useful when switching between debug and release builds.

Additionally, you can build your project by running "make" in the terminal, or "make BUILD=Debug", and run "make clean" to clean your project.
There are also Visual Studio Code tasks for building and cleaning your project, which you can find in the "Tasks: Run Task" command.

And finally, you can debug your project by pressing F5. You will first need to have a GDB server running in the background, which you can do by running the "PSX.Dev: Launch PCSX-Redux" command. Please note that debugging won't work unless the recommended tools are installed.

Don't forget that you can always open the main PSX.Dev panel by pressing Ctrl+Shift+P and running the "PSX.Dev: Show panel" command, in order to get all of the relevant documentation and links from the TEMPLATES tab.
`
  )

  await git.add('.gitignore')

  return git
}

async function createEmptyProject(fullPath, name, progressReporter) {
  const git = await createSkeleton(fullPath, name, progressReporter)
  await fs.writeFile(
    path.join(fullPath, 'main.c'),
    `
#include "third_party/nugget/common/syscalls/syscalls.h"

int main() {
    ramsyscall_printf("Hello world!\\n");
    while (1)
        ;
}
`
  )
  await fs.writeFile(
    path.join(fullPath, 'Makefile'),
    `
TARGET = ${name}
TYPE = ps-exe

SRCS = \
third_party/nugget/common/syscalls/printf.c \
third_party/nugget/common/crt0/crt0.s \
main.c

include third_party/nugget/common.mk
`
  )
  await git.add(['main.c', 'Makefile'])
}

async function createPsyQProject(fullPath, name, progressReporter, tools) {
  const git = await createSkeleton(fullPath, name, progressReporter)

  await fs.writeFile(
    path.join(fullPath, 'main.c'),
    `
#include <libetc.h>
#include <libgpu.h>
#include <libgte.h>
#include <stdlib.h>

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

        FntPrint("Code compiled using Psy-Q libraries\\n\\n");
        FntPrint("converted by psyq-obj-parser\\n\\n");
        FntPrint("PCSX-Redux project\\n\\n");
        FntPrint("https://bit.ly/pcsx-redux");

        add_cube(cdb->ot, cdb->s, &transform);

        DrawSync(0);
        VSync(0);

        ClearImage(&cdb->draw.clip, 60, 120, 120);

        DrawOTag(&cdb->ot[OTSIZE - 1]);
        FntFlush(-1);
    }

    return 0;
}
`
  )
  await fs.writeFile(
    path.join(fullPath, 'Makefile'),
    `
TARGET = ${name}
TYPE = ps-exe

SRCS = \
third_party/nugget/common/crt0/crt0.s \
main.c

CPPFLAGS += -Ithird_party/psyq-iwyu/include
LDFLAGS += -Lthird_party/psyq/lib
LDFLAGS += -Wl,--start-group
LDFLAGS += -lapi
LDFLAGS += -lc
LDFLAGS += -lc2
LDFLAGS += -lcard
LDFLAGS += -lcd
LDFLAGS += -lcomb
LDFLAGS += -lds
LDFLAGS += -letc
LDFLAGS += -lgpu
LDFLAGS += -lgs
LDFLAGS += -lgte
LDFLAGS += -lgun
LDFLAGS += -lhmd
LDFLAGS += -lmath
LDFLAGS += -lmcrd
LDFLAGS += -lmcx
LDFLAGS += -lpad
LDFLAGS += -lpress
LDFLAGS += -lsio
LDFLAGS += -lsnd
LDFLAGS += -lspu
LDFLAGS += -ltap
LDFLAGS += -Wl,--end-group

include third_party/nugget/common.mk
`
  )
  await git.submoduleAdd(
    'https://github.com/johnbaumann/psyq_include_what_you_use.git',
    'third_party/psyq-iwyu'
  )
  await tools.psyq.unpack(path.join(fullPath, 'third_party', 'psyq'))
  await git.add(['main.c', 'Makefile'])
}

async function createPSYQoProject(fullPath, name, progressReporter) {
  const git = await createSkeleton(fullPath, name, progressReporter)

  await fs.writeFile(
    path.join(fullPath, 'main.cpp'),
    `
#include "third_party/nugget/common/syscalls/syscalls.h"
#include "third_party/nugget/psyqo/application.hh"
#include "third_party/nugget/psyqo/font.hh"
#include "third_party/nugget/psyqo/gpu.hh"
#include "third_party/nugget/psyqo/scene.hh"

namespace {

// A PSYQo software needs to declare one \`Application\` object.
// This is the one we're going to do for our hello world.
class Hello final : public psyqo::Application {

    void prepare() override;
    void createScene() override;

  public:
    psyqo::Font<> m_font;
};

// And we need at least one scene to be created.
// This is the one we're going to do for our hello world.
class HelloScene final : public psyqo::Scene {
    void frame() override;

    // We'll have some simple animation going on, so we
    // need to keep track of our state here.
    uint8_t m_anim = 0;
    bool m_direction = true;
};

// We're instantiating the two objects above right now.
Hello hello;
HelloScene helloScene;

}  // namespace

void Hello::prepare() {
    psyqo::GPU::Configuration config;
    config.set(psyqo::GPU::Resolution::W320)
        .set(psyqo::GPU::VideoMode::AUTO)
        .set(psyqo::GPU::ColorMode::C15BITS)
        .set(psyqo::GPU::Interlace::PROGRESSIVE);
    gpu().initialize(config);
}

void Hello::createScene() {
    m_font.uploadSystemFont(gpu());
    pushScene(&helloScene);
}

void HelloScene::frame() {
    if (m_anim == 0) {
        m_direction = true;
    } else if (m_anim == 255) {
        m_direction = false;
    }
    psyqo::Color bg{{.r = 0, .g = 64, .b = 91}};
    bg.r = m_anim;
    hello.gpu().clear(bg);
    if (m_direction) {
        m_anim++;
    } else {
        m_anim--;
    }

    psyqo::Color c = {{.r = 255, .g = 255, .b = uint8_t(255 - m_anim)}};
    hello.m_font.print(hello.gpu(), "Hello World!", {{.x = 16, .y = 32}}, c);
}

int main() { return hello.run(); }
`
  )
  await fs.writeFile(
    path.join(fullPath, 'Makefile'),
    `
TARGET = ${name}
TYPE = ps-exe

SRCS = \
main.cpp

include third_party/nugget/psyqo/psyqo.mk
`
  )
  await git.add(['main.cpp', 'Makefile'])
}

const templates = {
  empty: {
    name: 'Empty',
    description:
      'An empty project, with just the barebone setup to get started.',
    requiredTools: ['git', 'make', 'toolchain'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: createEmptyProject
  },
  psyq: {
    name: 'Psy-Q SDK',
    description:
      'A project using the Psy-Q SDK. Please note that while it is probably considered abandonware at this point, you will not receive a proper license from Sony. Use it at your own risk. Additionally, while the project folder on your harddrive will have the SDK installed on it, the created git repository will not. If you publish the created git repository, users who clone it will need to restore the SDK using the WELCOME page button.',
    url: 'https://psx.arthus.net/sdk/Psy-Q/DOCS/',
    examples: 'https://github.com/ABelliqueux/nolibgs_hello_worlds',
    requiredTools: ['git', 'make', 'toolchain', 'psyq'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: createPsyQProject
  },
  psyqo: {
    name: 'PSYQo SDK',
    description:
      'A project using the PSYQo SDK. The PSYQo library is a C++-20 MIT-licensed framework cleanly written from scratch, allowing you to write modern, readable code targetting the PlayStation 1, while still being efficient. Additionally, you will have access to the EASTL library, which is a BSD-3-Clause licensed implementation of the C++ Standard Template Library.',
    url: 'https://github.com/pcsx-redux/nugget/tree/main/psyqo#how',
    examples: 'https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips/psyqo/examples',
    requiredTools: ['git', 'make', 'toolchain'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: createPSYQoProject
  }
}

exports.list = templates

exports.createProjectFromTemplate = async function (tools, options) {
  const fullPath = path.join(options.path, options.name)
  const template = templates[options.template]
  if (!template) {
    throw new Error('Unknown template: ' + options.template)
  }
  if (options.name === '') {
    throw new Error('The project name cannot be empty.')
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(options.name)) {
    throw new Error(
      'The project name contains invalid characters. Please use only letters, numbers, dashes and underscores.'
    )
  }
  if (!(await fs.stat(options.path)).isDirectory()) {
    throw new Error('The parent path does not exist.')
  }
  if (await fs.exists(fullPath)) {
    throw new Error('The project directory already exists.')
  }
  let resolver
  let rejecter
  const { progressReporter, progressResolver } =
    await progressNotification.notify(
      'Creating project...',
      'Creating directories...'
    )
  const ret = new Promise((resolve, reject) => {
    resolver = resolve
    rejecter = reject
  })
  template
    .create(fullPath, options.name, progressReporter, tools)
    .then(() => {
      progressResolver()
      resolver(fullPath)
    })
    .catch((err) => {
      progressResolver()
      rejecter(err)
    })
  return ret
}
