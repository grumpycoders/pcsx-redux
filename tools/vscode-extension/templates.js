'use strict'

const path = require('node:path')
const fs = require('fs-extra')
const Mustache = require('mustache')
const { simpleGit } = require('simple-git')
const progressNotification = require('./progressnotification.js')

let extensionUri

function combine (a, b) {
  const arraysThatAreInFactObjects = {
    configurations: 'name',
    tasks: 'label',
    files: 'name',
    modules: 'name'
  }

  function arrayToObject (array, subKeyName) {
    const result = {}
    for (const item of array) {
      if (typeof item !== 'object') throw new Error('Invalid array.')
      const newObject = {}
      for (const key in item) {
        if (key !== subKeyName) {
          newObject[key] = item[key]
        }
      }
      result[item[subKeyName]] = newObject
    }
    return result
  }

  function objectToArray (object, subKeyName) {
    const result = []
    for (const key in object) {
      if (typeof object[key] !== 'object') throw new Error('Invalid object.')
      const newObject = {}
      newObject[subKeyName] = key
      for (const subKey in object[key]) {
        newObject[subKey] = object[key][subKey]
      }
      result.push(newObject)
    }
    return result
  }

  if (Array.isArray(a) && Array.isArray(b)) {
    return a.concat(b)
  } else if (typeof a === 'object' && typeof b === 'object') {
    const result = {}
    for (const key in a) {
      result[key] = a[key]
    }
    for (const key in b) {
      if (key in result) {
        if (
          Array.isArray(a[key]) &&
          Array.isArray(b[key]) &&
          key in arraysThatAreInFactObjects
        ) {
          const subKeyName = arraysThatAreInFactObjects[key]
          result[key] = objectToArray(
            combine(
              arrayToObject(a[key], subKeyName),
              arrayToObject(b[key], subKeyName)
            ),
            subKeyName
          )
        } else {
          result[key] = combine(result[key], b[key])
        }
      } else {
        result[key] = b[key]
      }
    }
    return result
  } else {
    throw new Error('Cannot combine objects of unknown or different types.')
  }
}

/* eslint-disable no-template-curly-in-string */
const baseTemplate = {
  files: [
    {
      name: '.vscode/c_cpp_properties.json',
      type: 'json',
      content: {
        configurations: [
          {
            compilerPath:
              '${env:AppData}\\mips\\mips\\bin\\mipsel-none-elf-gcc.exe',
            cStandard: 'c17',
            cppStandard: 'c++20',
            defines: ['__STDC_HOSTED__ = 0'],
            includePath: [
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
              '/usr/mipsel-linux-gnu/include',
              '/usr/mipsel-none-elf/include'
            ],
            intelliSenseMode: 'gcc-x86',
            name: 'linux'
          }
        ],
        version: 4
      }
    },
    {
      name: '.vscode/launch.json',
      type: 'json',
      content: {
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
            stopAtConnect: true,
            gdbpath: 'gdb-multiarch',
            windows: {
              gdbpath: 'gdb-multiarch.exe'
            },
            osx: {
              gdbpath: 'gdb'
            }
          }
        ]
      }
    }
  ]
}

const baseNuggetTemplate = combine(baseTemplate, {
  files: [
    {
      name: '.vscode/c_cpp_properties.json',
      content: {
        configurations: [
          {
            includePath: [
              '${workspaceFolder}/',
              '${workspaceFolder}/third_party/nugget'
            ],
            name: 'Win32'
          },
          {
            includePath: [
              '${workspaceFolder}/',
              '${workspaceFolder}/third_party/nugget'
            ],
            name: 'linux'
          }
        ]
      }
    },
    {
      name: '.vscode/launch.json',
      content: {
        configurations: [
          {
            name: 'Debug',
            executable: '${workspaceRoot}/${workspaceRootFolderName}.elf',
            autorun: [
              'monitor reset shellhalt',
              'load ${workspaceRootFolderName}.elf',
              'tbreak main',
              'continue'
            ]
          }
        ]
      }
    },
    {
      name: '.vscode/tasks.json',
      type: 'json',
      content: {
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
      }
    },
    {
      name: '.gitignore',
      type: 'textarray',
      content: [
        '*.elf',
        '*.map',
        '*.cpe',
        '*.ps-exe',
        '*.dep',
        '*.o',
        '*.a',
        'PSX.Dev-README.md'
      ]
    }
  ],
  modules: [
    {
      name: 'third_party/nugget',
      url: 'https://github.com/pcsx-redux/nugget.git'
    }
  ]
})

const baseCMakeTemplate = combine(baseTemplate, {
  files: [
    {
      name: '.vscode/c_cpp_properties.json',
      content: {
        configurations: [
          {
            configurationProvider: 'ms-vscode.cmake-tools',
            includePath: ['${workspaceFolder}/src'],
            name: 'Win32'
          },
          {
            configurationProvider: 'ms-vscode.cmake-tools',
            includePath: ['${workspaceFolder}/src'],
            name: 'linux'
          }
        ]
      }
    },
    {
      name: '.vscode/launch.json',
      content: {
        configurations: [
          {
            name: 'Debug',
            executable: '${workspaceRoot}/build/${workspaceRootFolderName}.elf',
            autorun: [
              'monitor reset shellhalt',
              'load build/${workspaceRootFolderName}.elf',
              'tbreak main',
              'continue'
            ]
          }
        ]
      }
    },
    {
      name: '.vscode/settings.json',
      type: 'json',
      content: {
        'C_Cpp.default.configurationProvider': 'ms-vscode.cmake-tools'
      }
    },
    {
      name: '.vscode/tasks.json',
      type: 'json',
      content: {
        version: '2.0.0',
        tasks: [
          {
            label: 'Configure Debug',
            type: 'cmake',
            command: 'configure',
            preset: 'debug',
            group: {
              kind: 'build'
            }
          },
          {
            label: 'Configure Release',
            type: 'cmake',
            command: 'configure',
            preset: 'release',
            group: {
              kind: 'build'
            }
          },
          {
            label: 'Configure Minimum Size Release',
            type: 'cmake',
            command: 'configure',
            preset: 'min-size-release',
            group: {
              kind: 'build'
            }
          },
          {
            label: 'Build Debug',
            type: 'cmake',
            command: 'build',
            targets: ['all'],
            dependsOn: 'Configure Debug',
            group: {
              kind: 'build',
              isDefault: true
            },
            problemMatcher: ['$gcc']
          },
          {
            label: 'Build Release',
            type: 'cmake',
            command: 'build',
            targets: ['all'],
            dependsOn: 'Configure Release',
            group: {
              kind: 'build',
              isDefault: true
            },
            problemMatcher: ['$gcc']
          },
          {
            label: 'Build Minimum Size Release',
            type: 'cmake',
            command: 'build',
            targets: ['all'],
            dependsOn: 'Configure Minimum Size Release',
            group: {
              kind: 'build',
              isDefault: true
            },
            problemMatcher: ['$gcc']
          },
          {
            label: 'Clean',
            type: 'cmake',
            command: 'clean',
            group: {
              kind: 'build'
            }
          }
        ]
      }
    },
    {
      name: '.gitignore',
      type: 'textarray',
      content: [
        'build/',
        '.cache/',
        '__pycache__/',
        '*.pyc',
        '*.pyo',
        'CMakeUserPresets.json',
        'PSX.Dev-README.md'
      ]
    }
  ]
})

const bareMetalCMakeTemplate = combine(baseCMakeTemplate, {
  files: [
    {
      name: '.vscode/c_cpp_properties.json',
      content: {
        configurations: [
          {
            includePath: [
              '${workspaceFolder}/ps1-bare-metal/src',
              '${workspaceFolder}/ps1-bare-metal/src/libc'
            ],
            name: 'Win32'
          },
          {
            includePath: [
              '${workspaceFolder}/ps1-bare-metal/src',
              '${workspaceFolder}/ps1-bare-metal/src/libc'
            ],
            name: 'linux'
          }
        ]
      }
    }
  ],
  modules: [
    {
      name: 'ps1-bare-metal',
      url: 'https://github.com/spicyjpeg/ps1-bare-metal.git'
    }
  ]
})

const psyqoTemplate = combine(baseNuggetTemplate, {
  files: [
    {
      name: '.vscode/c_cpp_properties.json',
      content: {
        configurations: [
          {
            includePath: [
              '${workspaceFolder}/third_party/nugget/third_party/EASTL/include',
              '${workspaceFolder}/third_party/nugget/third_party/EABase/include/common'
            ],
            name: 'Win32'
          },
          {
            includePath: [
              '${workspaceFolder}/third_party/nugget/third_party/EASTL/include',
              '${workspaceFolder}/third_party/nugget/third_party/EABase/include/common'
            ],
            name: 'linux'
          }
        ]
      }
    }
  ]
})

const psyqTemplate = combine(baseNuggetTemplate, {
  files: [
    {
      name: '.vscode/c_cpp_properties.json',
      content: {
        configurations: [
          {
            includePath: ['${workspaceFolder}/third_party/psyq-iwyu/include'],
            name: 'Win32'
          },
          {
            includePath: ['${workspaceFolder}/third_party/psyq-iwyu/include'],
            name: 'linux'
          }
        ]
      }
    },
    {
      name: '.gitignore',
      content: ['third_party/psyq']
    }
  ],
  modules: [
    {
      name: 'third_party/psyq-iwyu',
      url: 'https://github.com/johnbaumann/psyq_include_what_you_use.git'
    }
  ]
})

const netyarozeTemplate = combine(psyqTemplate, {
  files: [
    {
      name: '.vscode/c_cpp_properties.json',
      content: {
        configurations: [
          {
            includePath: [
              '${workspaceFolder}/third_party/net-yaroze/include'
            ],
            name: 'Win32'
          },
          {
            includePath: [
              '${workspaceFolder}/third_party/net-yaroze/include'
            ],
            name: 'linux'
          }
        ]
      }
    }
  ],
  modules: [
    {
      name: 'third_party/net-yaroze',
      url: 'https://github.com/gwald/psyq_to_netyaroze.git'
    }
  ]
})
/* eslint-enable no-template-curly-in-string */

async function createGitRepository (fullPath, template, progressReporter) {
  progressReporter.report({ message: 'Generating files...' })
  await fs.mkdirp(fullPath)
  const git = simpleGit(fullPath)
  await git.init()
  await fs.copy(
    path.join(extensionUri.fsPath, 'templates', 'common', 'PSX.Dev-README.md'),
    path.join(fullPath, 'PSX.Dev-README.md')
  )
  if (template.files) {
    for (const file of template.files) {
      await fs.mkdirp(path.join(fullPath, path.dirname(file.name)))
      const fileFullPath = path.join(fullPath, file.name)
      if (file.type === 'json') {
        await fs.writeFile(fileFullPath, JSON.stringify(file.content, null, 2))
      } else if (file.type === 'text') {
        await fs.writeFile(fileFullPath, file.content)
      } else if (file.type === 'textarray') {
        await fs.writeFile(fileFullPath, file.content.join('\n'))
      }
      await git.add(fileFullPath)
    }
  }
  if (template.modules) {
    progressReporter.report({ message: 'Adding submodules...' })
    for (const module of template.modules) {
      await fs.mkdirp(path.join(fullPath, path.dirname(module.name)))
      await git.submoduleAdd(module.url, module.name)
    }
  }

  return git
}

async function copyTemplateDirectory (git, fullPath, name, template, data) {
  const files = await fs.readdir(template)
  for (const file of files) {
    const filePath = path.join(template, file)
    const stats = await fs.stat(filePath)
    if (stats.isFile()) {
      const content = await fs.readFile(filePath, 'utf8')
      const rendered = Mustache.render(content, data)
      await fs.writeFile(path.join(fullPath, file), rendered)
      await git.add(path.join(fullPath, file))
    } else if (stats.isDirectory()) {
      await fs.mkdirp(path.join(fullPath, file))
      await copyTemplateDirectory(
        git,
        path.join(fullPath, file),
        name,
        filePath
      )
    }
  }
}

const templates = {
  empty_nugget: {
    name: 'Empty (Nugget)',
    category: 'Bare metal',
    description:
      'An empty project, with just the barebone setup to get started.',
    url: 'https://github.com/pcsx-redux/nugget/blob/main/doc/README.md',
    examples: 'https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips',
    requiredTools: ['git', 'make', 'toolchain'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: async function (fullPath, name, progressReporter) {
      const git = await createGitRepository(
        fullPath,
        baseNuggetTemplate,
        progressReporter
      )
      await copyTemplateDirectory(
        git,
        fullPath,
        name,
        path.join(extensionUri.fsPath, 'templates', 'bare-metal', 'empty-nugget'),
        { projectName: name }
      )
    }
  },
  empty_cmake: {
    name: 'Empty (CMake)',
    category: 'Bare metal',
    description:
      'An empty project, with just the barebone setup to get started using a CMake-based build system.',
    url: 'https://github.com/spicyjpeg/ps1-bare-metal',
    examples: 'https://github.com/spicyjpeg/ps1-bare-metal/blob/main/README.md',
    requiredTools: ['git', 'make', 'cmake', 'toolchain'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: async function (fullPath, name, progressReporter) {
      const git = await createGitRepository(
        fullPath,
        bareMetalCMakeTemplate,
        progressReporter
      )
      await copyTemplateDirectory(
        git,
        fullPath,
        name,
        path.join(extensionUri.fsPath, 'templates', 'bare-metal', 'empty-cmake'),
        { projectName: name }
      )
    }
  },
  psyq_cube: {
    name: 'Psy-Q Cube',
    category: 'Psy-Q SDK',
    description:
      'A project showing a spinning cube using the Psy-Q SDK.',
    url: 'https://psx.arthus.net/sdk/Psy-Q/DOCS/',
    examples: 'https://github.com/ABelliqueux/nolibgs_hello_worlds',
    requiredTools: ['git', 'make', 'toolchain', 'psyq'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: async function (fullPath, name, progressReporter, tools) {
      const git = await createGitRepository(
        fullPath,
        psyqTemplate,
        progressReporter
      )
      await copyTemplateDirectory(
        git,
        fullPath,
        name,
        path.join(extensionUri.fsPath, 'templates', 'psyq', 'cube'),
        { projectName: name }
      )
      progressReporter.report({ message: 'Unpacking psyq...' })
      await tools.psyq.unpack(path.join(fullPath, 'third_party', 'psyq'))
    }
  },
  psyqo_hello: {
    name: 'PSYQo Hello World',
    category: 'PSYQo SDK',
    description:
      'A project simply displaying Hello World using the PSYQo SDK.',
    url: 'https://github.com/pcsx-redux/nugget/tree/main/psyqo#how',
    examples:
      'https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips/psyqo/examples',
    requiredTools: ['git', 'make', 'toolchain'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: async function (fullPath, name, progressReporter) {
      const git = await createGitRepository(
        fullPath,
        psyqoTemplate,
        progressReporter
      )
      await copyTemplateDirectory(
        git,
        fullPath,
        name,
        path.join(extensionUri.fsPath, 'templates', 'psyqo', 'hello'),
        { projectName: name }
      )
    }
  },
  psyq_netyaroze: {
    name: 'Net Yaroze Sprite',
    category: 'Psy-Q SDK',
    description:
      'A SCEE Net Yaroze tutorial showing 2D sprite movement, scaling and rotation using a subset of Psy-Q SDK (full compatibility is still Work In Progress).',
    url: 'https://github.com/gwald/psyq_to_netyaroze/',
    examples: 'https://github.com/gwald/netyaroze_demo',
    requiredTools: ['git', 'make', 'toolchain', 'psyq'],
    recommendedTools: ['gdb', 'debugger', 'redux'],
    create: async function (fullPath, name, progressReporter, tools) {
      const git = await createGitRepository(
        fullPath,
        netyarozeTemplate,
        progressReporter
      )

      await copyTemplateDirectory(
        git,
        fullPath,
        name,
        path.join(extensionUri.fsPath, 'templates', 'psyq', 'net-yaroze'),
        { projectName: name }
      )
      progressReporter.report({ message: 'Unpacking Net Yaroze...' })
      await tools.psyq.unpack(path.join(fullPath, 'third_party', 'psyq'))
    }
  }
}

exports.list = templates
exports.categories = {
  'Bare metal': {
    description: 'Bare metal projects. These examples are using little to no external dependencies to work.'
  },
  'Psy-Q SDK': {
    description: 'Projects using the Psy-Q SDK. This SDK was the original one published by Sony to create software for the PlayStation 1. Please note that while it is probably considered abandonware at this point, you will not receive a proper license from Sony. Use it at your own risk. Additionally, while the project folder on your harddrive will have the SDK installed on it, the created git repository will not. If you publish the created git repository, users who clone it will need to restore the SDK using the WELCOME page button.'
  },
  'PSYQo SDK': {
    description: 'Projects using the PSYQo SDK. The PSYQo library is a C++-20 MIT-licensed framework cleanly written from scratch, allowing you to write modern, readable code targeting the PlayStation 1, while still being efficient. Additionally, you will have access to the EASTL library, which is a BSD-3-Clause licensed implementation of the C++ Standard Template Library.'
  }
}
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
