'use strict'

const templates = {
  empty: {
    name: 'Empty',
    description:
      'An empty project, with just the barebone setup to get started.',
    requiredTools: ['git', 'make', 'toolchain', 'gdb'],
    recommendedTools: ['gdb', 'debugger', 'redux']
  },
  psyq: {
    name: 'Psy-Q SDK',
    description:
      'A project using the Psy-Q SDK. Please note that while the Psy-Q is probably considered abandonware at this point, you will not receive a proper license from Sony. Use it at your own risks. Additionally, the created git directory will not have the SDK itself stored on it, and as a result, users will need to restore the SDK after cloning the project.',
    url: 'https://psx.arthus.net/sdk/Psy-Q/DOCS/',
    requiredTools: ['git', 'make', 'toolchain', 'gdb', 'psyq'],
    recommendedTools: ['gdb', 'debugger', 'redux']
  },
  psyqo: {
    name: 'PSYQo SDK',
    description:
      'A project using the PSYQo SDK. The PSYQo library is a C++-20 MIT-licensed framework written from scratch, allowing you to write modern, readable code targetting the PlayStation 1, while still being efficient.',
    url: 'https://github.com/pcsx-redux/nugget/tree/main/psyqo#how',
    requiredTools: ['git', 'make', 'toolchain', 'gdb'],
    recommendedTools: ['gdb', 'debugger', 'redux']
  }
}

exports.list = templates
