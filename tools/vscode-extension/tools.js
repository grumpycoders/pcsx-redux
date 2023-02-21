'use strict'

const vscode = require('vscode')
const util = require('node:util')
const execAsync = require('node:child_process').exec
const terminal = require('./terminal.js')
const exec = util.promisify(execAsync)

const mipsVersion = '12.2.0'
let extensionUri

async function checkInstalled (name) {
  if (tools[name].installed === undefined) {
    tools[name].installed = await tools[name].check()
  }
  return tools[name].installed
}

function checkSimpleCommand (command) {
  return new Promise((resolve) => {
    execAsync(command, (error) => {
      if (error) {
        resolve(false)
      } else {
        resolve(true)
      }
    })
  })
}

async function installMips () {
  try {
    await terminal.run('powershell', [
      '-c "& { iwr -UseBasicParsing https://bit.ly/mips-ps1 | iex }"'
    ])
    vscode.window.showInformationMessage(
      'Installing the MIPS tool requires a reboot. Please reboot your computer before proceeding further.'
    )
  } catch (error) {
    vscode.window.showErrorMessage(
      'An error occurred while installing the MIPS toolchain. Please install it manually.'
    )
    throw error
  }
}

async function installToolchain () {
  switch (process.platform) {
    case 'win32':
      try {
        if (!(await checkInstalled('mips'))) {
          await installMips()
        } else {
          await terminal.run('mips', ['install', mipsVersion])
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing the MIPS toolchain. Please install it manually.'
        )
        throw error
      }
      break
    case 'linux':
      try {
        if (await checkInstalled('apt')) {
          execAsync('xdg-open apt:mipsel-linux-gnu-g++')
        } else if (await checkInstalled('trizen')) {
          await terminal.run('trizen', [
            '-S',
            'cross-mipsel-linux-gnu-binutils',
            'cross-mipsel-linux-gnu-gcc'
          ])
        } else if (await checkInstalled('brew')) {
          const binutilsScriptPath = vscode.Uri.joinPath(
            extensionUri,
            'scripts',
            'mipsel-none-elf-binutils.rb'
          )
          const gccScriptPath = vscode.Uri.joinPath(
            extensionUri,
            'scripts',
            'mipsel-none-elf-binutils.rb'
          )
          await terminal.run('brew', [
            'install',
            binutilsScriptPath,
            gccScriptPath
          ])
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install the MIPS toolchain manually.'
          )
          return Promise.reject(new Error('Unsupported platform'))
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing the MIPS toolchain. Please install it manually.'
        )
        throw error
      }
      break
    case 'darwin':
      try {
        if (await checkInstalled('brew')) {
          const binutilsScriptPath = vscode.Uri.joinPath(
            extensionUri,
            'scripts',
            'mipsel-none-elf-binutils.rb'
          )
          const gccScriptPath = vscode.Uri.joinPath(
            extensionUri,
            'scripts',
            'mipsel-none-elf-binutils.rb'
          )
          await terminal.run('brew', [
            'install',
            binutilsScriptPath,
            gccScriptPath
          ])
        } else {
          await terminal.run('/bin/bash', [
            '-c',
            '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'
          ])
          vscode.window.showInformationMessage(
            'Installing the Brew tool requires a reboot. Please reboot your computer before proceeding further.'
          )
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing the MIPS toolchain. Please install it manually.'
        )
        throw error
      }
      break
    default:
      vscode.window.showErrorMessage(
        'Your platform is not supported by this extension. Please install the MIPS toolchain manually.'
      )
      return Promise.reject(new Error('Unsupported platform'))
  }
}

function checkToolchain () {
  return Promise.any([
    exec('mipsel-linux-gnu-g++ --version'),
    exec('mipsel-none-elf-g++ --version')
  ])
}

async function installGDB () {
  switch (process.platform) {
    case 'win32':
      try {
        if (!(await checkInstalled('mips'))) {
          await installMips()
        } else {
          await terminal.run('mips', ['install', mipsVersion])
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing GDB Multiarch. Please install it manually.'
        )
        throw error
      }
      break
    case 'linux':
      try {
        if (await checkInstalled('apt')) {
          execAsync('xdg-open apt:gdb-multiarch')
        } else if (await checkInstalled('trizen')) {
          await terminal.run('trizen', ['-S', 'gdb-multiarch'])
        } else if (await checkInstalled('brew')) {
          await terminal.run('brew', ['install', 'gdb-multiarch'])
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install the MIPS toolchain manually.'
          )
          return Promise.reject(new Error('Unsupported platform'))
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing GDB Multiarch. Please install it manually.'
        )
        throw error
      }
      break
    case 'darwin':
      try {
        if (await checkInstalled('brew')) {
          await terminal.run('brew', ['install', 'gdb-multiarch'])
        } else {
          await terminal.run('/bin/bash', [
            '-c',
            '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'
          ])
          vscode.window.showInformationMessage(
            'Installing the Brew tool requires a reboot. Please reboot your computer before proceeding further.'
          )
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing GDB Multiarch. Please install it manually.'
        )
        throw error
      }
      break
    default:
      vscode.window.showErrorMessage(
        'Your platform is not supported by this extension. Please install GDB Multiarch manually.'
      )
      return Promise.reject(new Error('Unsupported platform'))
  }
}

async function installMake () {
  switch (process.platform) {
    case 'win32':
      try {
        if (!(await checkInstalled('mips'))) {
          await installMips()
        } else {
          await terminal.run('mips', ['install', mipsVersion])
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing GNU Make. Please install it manually.'
        )
        throw error
      }
      break
    case 'linux':
      try {
        if (await checkInstalled('apt')) {
          execAsync('xdg-open apt:build-essential')
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install the MIPS toolchain manually.'
          )
          return Promise.reject(new Error('Unsupported platform'))
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing GNU Make. Please install it manually.'
        )
        throw error
      }
      break
    case 'darwin':
      try {
        if (await checkInstalled('brew')) {
          await terminal.run('brew', ['install', 'gdb-multiarch'])
        } else {
          await terminal.run('/bin/bash', [
            '-c',
            '$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)'
          ])
          vscode.window.showInformationMessage(
            'Installing the Brew tool requires a reboot. Please reboot your computer before proceeding further.'
          )
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing GNU Make. Please install it manually.'
        )
        throw error
      }
      break
    default:
      vscode.window.showErrorMessage(
        'Your platform is not supported by this extension. Please install GNU Make manually.'
      )
      return Promise.reject(new Error('Unsupported platform'))
  }
}

const tools = {
  mips: {
    type: 'internal',
    install: installMips,
    check: () => checkSimpleCommand('mips --version')
  },
  apt: {
    type: 'internal',
    check: () => checkSimpleCommand('apt-get --version')
  },
  trizen: {
    type: 'internal',
    check: () => checkSimpleCommand('trizen --version')
  },
  brew: {
    type: 'internal',
    install: 'https://brew.sh/',
    check: () => checkSimpleCommand('brew --version')
  },
  toolchain: {
    type: 'package',
    name: 'MIPS Toolchain',
    description: 'The toolchain used to compile code for the PlayStation 1',
    install: installToolchain,
    check: checkToolchain
  },
  gdb: {
    type: 'package',
    name: 'GDB Multiarch',
    description: 'The tool to debug code for the PlayStation 1',
    install: installGDB,
    check: () => checkSimpleCommand('gdb-multiarch --version')
  },
  make: {
    type: 'package',
    name: 'GNU Make',
    description: 'Build code and various targets with this tool',
    install: installMake,
    check: () => checkSimpleCommand('make --version')
  },
  git: {
    type: 'package',
    name: 'Git',
    description: 'Tool to maintain your code, and initialize your project templates',
    install: 'https://git-scm.com/downloads',
    check: () => checkSimpleCommand('git --version')
  },
  clangd: {
    type: 'extension',
    name: 'clangd',
    description: 'A VSCode extension providing code completion within VSCode, and other features',
    id: 'llvm-vs-code-extensions.vscode-clangd'
  },
  debugger: {
    type: 'extension',
    name: 'Debugger connector',
    description: 'A VSCode extension to connect to the PlayStation 1 or an emulator, and debug your code',
    id: 'webfreak.debug'
  }
}

exports.refreshAll = async () => {
  for (const [, tool] of Object.entries(tools)) {
    if (tool.check) {
      try {
        tool.installed = await tool.check()
      } catch (error) {
        tool.installed = false
      }
    } else if (tool.type === 'extension') {
      tool.installed = vscode.extensions.getExtension(tool.id) !== undefined
    }
  }
  return tools
}

exports.list = tools
exports.setExtensionUri = (uri) => {
  extensionUri = uri
}
exports.install = async (tool) => {
  if (tools[tool].install) {
    if (typeof tools[tool].install === 'string') {
      vscode.env.openExternal(vscode.Uri.parse(tools[tool].install))
    } else {
      await tools[tool].install()
    }
  } else if (tools[tool].type === 'extension') {
    vscode.commands.executeCommand(
      'workbench.extensions.installExtension',
      tools[tool].id
    )
  }
}
