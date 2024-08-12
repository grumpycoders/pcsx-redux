'use strict'

const vscode = require('vscode')
const util = require('node:util')
const execAsync = require('node:child_process').exec
const exec = util.promisify(execAsync)
const terminal = require('./terminal.js')
const pcsxRedux = require('./pcsx-redux.js')
const fs = require('fs-extra')
const downloader = require('./downloader.js')
const unzipper = require('unzipper')
const path = require('node:path')
const { Octokit } = require('@octokit/rest')
const octokit = new Octokit()
const os = require('node:os')

const mipsVersion = '14.2.0'
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
let win32MipsToolsInstalling = false

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
          if (win32MipsToolsInstalling) return
          win32MipsToolsInstalling = true
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
          await terminal.run(
            'sudo',
            ['apt', 'install', 'g++-mipsel-linux-gnu'],
            {
              message: 'Installing the MIPS toolchain requires root privileges.'
            }
          )
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
          ).fsPath
          const gccScriptPath = vscode.Uri.joinPath(
            extensionUri,
            'scripts',
            'mipsel-none-elf-binutils.rb'
          ).fsPath
          await terminal.run('brew', [
            'install',
            binutilsScriptPath,
            gccScriptPath
          ])
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install the MIPS toolchain manually.'
          )
          throw new Error('Unsupported platform')
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
          ).fsPath
          const gccScriptPath = vscode.Uri.joinPath(
            extensionUri,
            'scripts',
            'mipsel-none-elf-binutils.rb'
          ).fsPath
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
      throw new Error('Unsupported platform')
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
          if (win32MipsToolsInstalling) return
          win32MipsToolsInstalling = true
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
          await terminal.run('sudo', ['apt', 'install', 'gdb-multiarch'], {
            message: 'Installing GDB Multiarch requires root privileges.'
          })
        } else if (await checkInstalled('trizen')) {
          await terminal.run('trizen', ['-S', 'gdb-multiarch'])
        } else if (await checkInstalled('brew')) {
          await terminal.run('brew', ['install', 'gdb-multiarch'])
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install the MIPS toolchain manually. Alternatively, you can install linuxbrew, and refresh this panel.'
          )
          throw new Error('Unsupported platform')
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
          await terminal.run('brew', ['install', 'gdb'])
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
          'An error occurred while installing GDB Multiarch. Please install it manually. Alternatively, you can install linuxbrew, and refresh this panel.'
        )
        throw error
      }
      break
    default:
      vscode.window.showErrorMessage(
        'Your platform is not supported by this extension. Please install GDB Multiarch manually.'
      )
      throw new Error('Unsupported platform')
  }
}

async function installMake () {
  switch (process.platform) {
    case 'win32':
      try {
        if (!(await checkInstalled('mips'))) {
          await installMips()
        } else {
          if (win32MipsToolsInstalling) return
          win32MipsToolsInstalling = true
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
          await terminal.run('sudo', ['apt', 'install', 'build-essential'], {
            message: 'Installing GNU Make requires root privileges.'
          })
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install the MIPS toolchain manually.'
          )
          throw new Error('Unsupported platform')
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
      throw new Error('Unsupported platform')
  }
}

async function installCMake () {
  switch (process.platform) {
    case 'win32':
      const release = await octokit.rest.repos.getLatestRelease({
        owner: 'Kitware',
        repo: 'CMake'
      })
      const asset = release.data.assets.find((asset) => {
        return /^cmake-.*-windows-x86_64\.msi/.test(asset.name)
      })
      if (!asset) {
        vscode.window.showErrorMessage(
          'Could not find the latest CMake release. Please install it manually.'
        )
        return
      }
      const filename = path.join(
        os.tmpdir(),
        asset.browser_download_url.split('/').pop()
      )
      await downloader.downloadFile(asset.browser_download_url, filename)
      await exec(`start ${filename}`)
      requiresReboot = true
      break
    case 'linux':
      try {
        if (await checkInstalled('apt')) {
          await terminal.run('sudo', ['apt', 'install', 'cmake'], {
            message: 'Installing CMake requires root privileges.'
          })
        } else if (await checkInstalled('trizen')) {
          await terminal.run('trizen', ['-S', 'cmake'])
        } else if (await checkInstalled('brew')) {
          await terminal.run('brew', ['install', 'cmake'])
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install CMake manually. Alternatively, you can install linuxbrew, and refresh this panel.'
          )
          throw new Error('Unsupported platform')
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing CMake. Please install it manually.'
        )
        throw error
      }
      break
    case 'darwin':
      try {
        if (await checkInstalled('brew')) {
          await terminal.run('brew', ['install', 'cmake'])
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
          'An error occurred while installing CMake. Please install it manually. Alternatively, you can install linuxbrew, and refresh this panel.'
        )
        throw error
      }
      break
    default:
      vscode.window.showErrorMessage(
        'Your platform is not supported by this extension. Please install CMake manually.'
      )
      throw new Error('Unsupported platform')
  }
}

async function installGit () {
  switch (process.platform) {
    case 'win32': {
      const release = await octokit.rest.repos.getLatestRelease({
        owner: 'git-for-windows',
        repo: 'git'
      })
      const asset = release.data.assets.find((asset) => {
        return /^Git-.*-64-bit\.exe/.test(asset.name)
      })
      if (!asset) {
        vscode.window.showErrorMessage(
          'Could not find the latest Git for Windows release. Please install it manually.'
        )
        return
      }
      const filename = path.join(
        os.tmpdir(),
        asset.browser_download_url.split('/').pop()
      )
      await downloader.downloadFile(asset.browser_download_url, filename)
      await exec(filename)
      requiresReboot = true
      break
    }
    case 'linux':
      if (await checkInstalled('apt')) {
        return terminal.run('sudo', ['apt', 'install', 'git'], {
          message: 'Installing Git requires root privileges.'
        })
      }
    // eslint-disable-next-line no-fallthrough -- intentional
    default:
      return vscode.env.openExternal(
        vscode.Uri.parse('https://git-scm.com/downloads')
      )
  }
}

async function installPython () {
  switch (process.platform) {
    case 'win32':
      const tags = await octokit.rest.repos.listTags({
        owner: 'python',
        repo: 'cpython'
      })
      let latestVersion = [3, 12, 0]
      for (const release of tags.data) {
        const match = /v(3)\.([0-9]+)\.([0-9]+)$/.exec(release.name)
        if (!match) {
          continue
        }
        const version = match.slice(1).map((value) => parseInt(value))
        if (version > latestVersion) {
          latestVersion = version
        }
      }
      const versionStr = latestVersion.join('.')
      const url = `https://python.org/ftp/python/${versionStr}/python-${versionStr}-amd64.exe`
      const filename = path.join(
        os.tmpdir(),
        url.split('/').pop()
      )
      await downloader.downloadFile(url, filename)
      await exec(filename)
      requiresReboot = true
      break
    case 'linux':
      try {
        if (await checkInstalled('apt')) {
          await terminal.run('sudo', ['apt', 'install', 'python3'], {
            message: 'Installing Python requires root privileges.'
          })
        } else if (await checkInstalled('brew')) {
          await terminal.run('brew', ['install', 'python@3.12'])
        } else {
          vscode.window.showErrorMessage(
            'Your Linux distribution is not supported. You need to install Python manually. Alternatively, you can install linuxbrew, and refresh this panel.'
          )
          throw new Error('Unsupported platform')
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          'An error occurred while installing Python. Please install it manually. Alternatively, you can install linuxbrew, and refresh this panel.'
        )
        throw error
      }
      break
    default:
      vscode.window.showErrorMessage(
        'Your platform is not supported by this extension. Please install Python manually.'
      )
      throw new Error('Unsupported platform')
  }
}

function checkPython () {
  switch (process.platform) {
    case 'win32':
      // On Windows "python" and "python3" are aliased to a script that opens
      // the Microsoft Store by default, so we must check for the "py" launcher
      // provided by the official installers instead.
      // TODO: try to detect other Python installations that do not come with
      // the py launcher (e.g. ones from MSys2)
      return checkSimpleCommand('py -3 --version')
    default:
      return Promise.any([
        exec('python --version'),
        exec('python3 --version')
      ])
  }
}

function unpackPsyq (destination) {
  const filename = vscode.Uri.joinPath(
    globalStorageUri,
    tools.psyq.filename
  ).fsPath

  return fs
    .createReadStream(filename)
    .pipe(unzipper.Parse())
    .on('entry', function (entry) {
      const fragments = entry.path.split('/')
      fragments.shift()
      const outputPath = path.join(destination, ...fragments)
      if (entry.type === 'Directory') {
        fs.mkdirSync(outputPath, { recursive: true })
        entry.autodrain()
      } else {
        entry.pipe(fs.createWriteStream(outputPath))
      }
    })
    .promise()
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
    check: () => checkGDB()
  },
  make: {
    type: 'package',
    name: 'GNU Make',
    description: 'Build code and various targets with this tool',
    homepage: 'https://www.gnu.org/software/make/',
    install: installMake,
    check: () => checkSimpleCommand('make --version')
  },
  cmake: {
    type: 'package',
    name: 'CMake',
    description: 'A more advanced building tool for projects that require it',
    homepage: 'https://cmake.org/',
    install: installCMake,
    check: () => checkSimpleCommand('cmake --version')
  },
  git: {
    type: 'package',
    name: 'Git',
    description:
      'Tool to maintain your code, and initialize your project templates',
    homepage: 'https://git-scm.com/',
    install: installGit,
    check: () => checkSimpleCommand('git --version')
  },
  python: {
    type: 'package',
    name: 'Python',
    description:
      'Python language runtime, required to run some project templates\' scripts',
    homepage: 'https://python.org/',
    install: installPython,
    check: checkPython
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
  cmaketools: {
    type: 'extension',
    name: 'CMake Tools extension',
    description:
      'A VSCode extension providing support for configuring and building CMake-based projects',
    homepage:
      'https://marketplace.visualstudio.com/items?itemName=ms-vscode.cmake-tools',
    id: 'ms-vscode.cmake-tools'
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
  mipsassembly: {
    type: 'extension',
    name: 'MIPS assembly extension',
    description:
      'A VSCode extension that provides syntax highlighting for MIPS assembly code',
    homepage:
      'https://marketplace.visualstudio.com/items?itemName=kdarkhan.mips',
    id: 'kdarkhan.mips'
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
    filename = vscode.Uri.joinPath(globalStorageUri, filename).fsPath
    fs.access(filename, fs.constants.F_OK, (err) => {
      resolve(!err)
    })
  })
}

function checkGDB () {
  if (process.platform === 'darwin') return checkSimpleCommand('gdb --version')
  return checkSimpleCommand('gdb-multiarch --version')
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
  if (requiresReboot) {
    return true
  }
  for (const tool of toInstall) {
    if (!force && (await checkInstalled(tool))) continue
    if (tools[tool].install) {
      if (typeof tools[tool].install === 'string') {
        vscode.env.openExternal(vscode.Uri.parse(tools[tool].install))
      } else {
        await tools[tool].install(force)
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
  win32MipsToolsInstalling = false
  return requiresReboot
}

exports.maybeInstall = async (toInstall) => {
  const installed = await checkInstalled(toInstall)
  if (!installed && !requiresReboot) {
    const ret = exports.install([toInstall])
    win32MipsToolsInstalling = false
    return ret
  }
  return requiresReboot
}
