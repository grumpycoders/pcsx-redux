'use strict'

const path = require('node:path')
const fs = require('fs-extra')
const Mustache = require('mustache')
const { simpleGit } = require('simple-git')
const progressNotification = require('./progressnotification.js')

let extensionUri

const stringify = (obj) => {
  return JSON.stringify(obj, null, 2)
}

async function createSkeleton (fullPath, name, progressReporter) {
  await fs.mkdirp(path.join(fullPath, '.vscode'))
  await fs.writeFile(
    path.join(fullPath, '.vscode', 'c_cpp_properties.json'),
    stringify({
      configurations: [
        {
          compilerPath:
            '${env:AppData}\\mips\\mips\\bin\\mipsel-none-elf-gcc.exe',
          cStandard: 'c17',
          cppStandard: 'c++20',
          defines: ['__STDC_HOSTED__ = 0'],
          includePath: [
            '${workspaceFolder}/',
            '${workspaceFolder}/third_party/nugget',
            '${workspaceFolder}/third_party/nugget/third_party/eastl/include',
            '${workspaceFolder}/third_party/nugget/third_party/eabase/include/common',
            '${env:AppData}/mips/mips/include'
          ],
          intelliSenseMode: 'gcc-x86',
          name: 'Win32'
        },
        {
          compilerPath: 'mipsel-linux-gnu-gcc',
          cStandard: 'c17',
          cppStandard: 'c++20',
          defines: ['__STDC_HOSTED__ = 0'],
          includePath: [
            '${workspaceFolder}/',
            '${workspaceFolder}/third_party/nugget',
            '${workspaceFolder}/third_party/nugget/third_party/eastl/include',
            '${workspaceFolder}/third_party/nugget/third_party/eabase/include/common',
            '/usr/mipsel-linux-gnu/include'
          ],
          intelliSenseMode: 'gcc-x86',
          name: 'linux'
        }
      ],
      version: 4
    })
  )
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
            gdbpath: 'gdb-multiarch.exe'
          },
          osx: {
            gdbpath: 'gdb'
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

  await fs.copy(
    path.join(extensionUri.fsPath, 'templates', 'common', 'PSX.Dev-README.md'),
    path.join(fullPath, 'PSX.Dev-README.md')
  )

  await git.add('.gitignore')

  return git
}

async function copyTemplate (git, fullPath, name, template) {
  const files = await fs.readdir(template)
  for (const file of files) {
    const filePath = path.join(template, file)
    const stats = await fs.stat(filePath)
    if (stats.isFile()) {
      const content = await fs.readFile(filePath, 'utf8')
      const rendered = Mustache.render(content, { projectName: name })
      await fs.writeFile(path.join(fullPath, file), rendered)
      await git.add(file)
    } else if (stats.isDirectory()) {
      await fs.mkdirp(path.join(fullPath, file))
      await copyTemplate(git, path.join(fullPath, file), name, filePath)
    }
  }
}

async function createEmptyBareMetalProject (fullPath, name, progressReporter) {
  const git = await createSkeleton(fullPath, name, progressReporter)
  await copyTemplate(git, fullPath, name, path.join(extensionUri.fsPath, 'templates', 'bare-metal', 'empty'))
}

async function createPsyQCubeProject (fullPath, name, progressReporter, tools) {
  const git = await createSkeleton(fullPath, name, progressReporter)
  await copyTemplate(git, fullPath, name, path.join(extensionUri.fsPath, 'templates', 'psyq', 'cube'))
  await git.submoduleAdd(
    'https://github.com/johnbaumann/psyq_include_what_you_use.git',
    'third_party/psyq-iwyu'
  )
  await tools.psyq.unpack(path.join(fullPath, 'third_party', 'psyq'))
}

async function createPSYQoHelloProject (fullPath, name, progressReporter) {
  const git = await createSkeleton(fullPath, name, progressReporter)
  await copyTemplate(git, fullPath, name, path.join(extensionUri.fsPath, 'templates', 'psyqo', 'hello'))
}

const templates = {
  empty: {
    name: 'Empty',
    category: 'Bare metal',
    description:
      'An empty project, with just the barebone setup to get started.',
    url: 'https://github.com/pcsx-redux/nugget/blob/main/doc/README.md',
    examples: 'https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips',
    requiredTools: ['git', 'make', 'toolchain'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: createEmptyBareMetalProject
  },
  psyq_cube: {
    name: 'Psy-Q Cube',
    category: 'Psy-Q SDK',
    description:
      'A project showing a spinning cube using the Psy-Q SDK. Please note that while it is probably considered abandonware at this point, you will not receive a proper license from Sony. Use it at your own risk. Additionally, while the project folder on your harddrive will have the SDK installed on it, the created git repository will not. If you publish the created git repository, users who clone it will need to restore the SDK using the WELCOME page button.',
    url: 'https://psx.arthus.net/sdk/Psy-Q/DOCS/',
    examples: 'https://github.com/ABelliqueux/nolibgs_hello_worlds',
    requiredTools: ['git', 'make', 'toolchain', 'psyq'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: createPsyQCubeProject
  },
  psyqo_hello: {
    name: 'PSYQo Hello World',
    category: 'PSYQo SDK',
    description:
      'A project simply displaying Hello World using the PSYQo SDK. The PSYQo library is a C++-20 MIT-licensed framework cleanly written from scratch, allowing you to write modern, readable code targetting the PlayStation 1, while still being efficient. Additionally, you will have access to the EASTL library, which is a BSD-3-Clause licensed implementation of the C++ Standard Template Library.',
    url: 'https://github.com/pcsx-redux/nugget/tree/main/psyqo#how',
    examples:
      'https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips/psyqo/examples',
    requiredTools: ['git', 'make', 'toolchain'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: createPSYQoHelloProject
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
  if (fullPath.includes(' ')) {
    throw new Error('The project path cannot contain spaces.')
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

exports.setExtensionUri = (uri) => {
  extensionUri = uri
}
