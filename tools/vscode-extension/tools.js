'use strict'

const vscode = require('vscode')
const util = require('node:util')
const execAsync = require('node:child_process').exec
const terminal = require('./terminal.js')
const pcsxRedux = require('./pcsx-redux.js')
const exec = util.promisify(execAsync)
const fs = require('node:fs')
const downloader = require('./downloader.js')

const mipsVersion = '12.2.0'
let extensionUri
let globalStorageUri
let requiresReboot = false

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

let mipsInstalling = false

async function installMips () {
  if (mipsInstalling) return
  mipsInstalling = true
  try {
    await terminal.run('powershell', [
      '-c "& { iwr -UseBasicParsing https://bit.ly/mips-ps1 | iex }"'
    ])
    requiresReboot = true
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
          terminal.run('sudo', ['apt', 'install', 'mipsel-linux-gnu-g++'], {
            message: 'Installing the MIPS toolchain requires root privileges.'
          })
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
          requiresReboot = true
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
          terminal.run('sudo', ['apt', 'install', 'gdb-multiarch'], {
            message: 'Installing GDB Multiarch requires root privileges.'
          })
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
          requiresReboot = true
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

function checkGDB () {
  if (process.platform === 'win32') {
    return checkSimpleCommand('gdb --version')
  } else {
    return checkSimpleCommand('gdb-multiarch --version')
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
          terminal.run('sudo', ['apt', 'install', 'build-essential'], {
            message: 'Installing GNU Make requires root privileges.'
          })
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
          requiresReboot = true
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

function unpackPsyq(destination) {
    return Promise.resolve()
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
    homepage: 'https://gcc.gnu.org/',
    install: installToolchain,
    check: checkToolchain
  },
  gdb: {
    type: 'package',
    name: 'GDB Multiarch',
    description: 'The tool to debug code for the PlayStation 1',
    homepage: 'https://www.sourceware.org/gdb/',
    install: installGDB,
    check: checkGDB
  },
  make: {
    type: 'package',
    name: 'GNU Make',
    description: 'Build code and various targets with this tool',
    homepage: 'https://www.gnu.org/software/make/',
    install: installMake,
    check: () => checkSimpleCommand('make --version')
  },
  git: {
    type: 'package',
    name: 'Git',
    description:
      'Tool to maintain your code, and initialize your project templates',
    homepage: 'https://git-scm.com/',
    install: 'https://git-scm.com/downloads',
    check: () => checkSimpleCommand('git --version')
  },
  clangd: {
    type: 'extension',
    name: 'clangd',
    description:
      'A VSCode extension providing code completion within VSCode, and other features',
    homepage:
      'https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd',
    id: 'llvm-vs-code-extensions.vscode-clangd'
  },
  debugger: {
    type: 'extension',
    name: 'Debugger connector',
    description:
      'A VSCode extension to connect to the PlayStation 1 or an emulator, and debug your code',
    homepage:
      'https://marketplace.visualstudio.com/items?itemName=webfreak.debug',
    id: 'webfreak.debug'
  },
  psyq: {
    type: 'archive',
    name: 'Psy-Q SDK',
    description:
      'The original SDK made by Sony used to develop code for the PlayStation 1. Please note that you are not going to receive a license to use this SDK from Sony by downloading it, and so using it should be at your own risks.',
    homepage: 'https://psx.arthus.net/sdk/Psy-Q/',
    filename: 'psyq-4_7-converted-light.zip',
    url: 'https://psx.arthus.net/sdk/Psy-Q/psyq-4_7-converted-light.zip',
    unpack: unpackPsyq
  },
  redux: {
    type: 'archive',
    name: 'PCSX-Redux',
    description:
      'A PlayStation 1 emulator focusing on development features, enabling you to debug your code easily.',
    homepage: 'https://pcsx-redux.consoledev.net/',
    launch: pcsxRedux.launch,
    install: pcsxRedux.install,
    check: pcsxRedux.check
  }
}

function checkLocalFile (filename) {
  return new Promise((resolve) => {
    filename = vscode.Uri.joinPath(globalStorageUri, filename)
    fs.access(filename.fsPath, fs.constants.F_OK, (err) => {
      resolve(!err)
    })
  })
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
    } else if (tool.type === 'archive') {
      tool.installed = await checkLocalFile(tool.filename)
    }
  }
  return tools
}

exports.list = tools

exports.setExtensionUri = (uri) => {
  extensionUri = uri
}

exports.setGlobalStorageUri = (uri) => {
  globalStorageUri = uri
}

exports.install = async (toInstall, force) => {
  for (const tool of toInstall) {
    if (!force && await checkInstalled(toInstall)) continue
    if (tools[tool].install) {
      if (typeof tools[tool].install === 'string') {
        vscode.env.openExternal(vscode.Uri.parse(tools[tool].install))
      } else {
        await tools[tool].install()
      }
    } else if (tools[tool].type === 'extension') {
      const extensionId = tools[tool].id
      await vscode.commands.executeCommand('extension.open', extensionId)
    } else if (tools[tool].type === 'archive') {
      await downloader.downloadFile(
        tools[tool].url,
        vscode.Uri.joinPath(globalStorageUri, tools[tool].filename).fsPath
      )
    }
  }
  return requiresReboot
}

exports.maybeInstall = (toInstall) => {
  return checkInstalled(toInstall).then((installed) => {
    if (!installed) return exports.install([toInstall])
    return Promise.resolve(false)
  })
}
