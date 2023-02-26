'use strict'

const vscode = require('vscode')
const Axios = require('axios').Axios
const axios = new Axios({})
const { mkdirp, copy } = require('fs-extra')
const jsonStream = require('JSONStream')
const path = require('path')
const downloader = require('./downloader.js')
const util = require('node:util')
const fs = require('fs-extra')
const dmg = require('dmg')
const dmgMount = util.promisify(dmg.mount)
const dmgUnmount = util.promisify(dmg.unmount)
const terminal = require('./terminal.js')
const execAsync = require('node:child_process').exec
const exec = util.promisify(execAsync)
const os = require('node:os')

const updateInfo = {
  win32: {
    updateCatalog:
      'https://install.appcenter.ms/api/v0.1/apps/grumpycoders/pcsx-redux-win64-cli/distribution_groups/public/public_releases',
    updateInfoBase:
      'https://install.appcenter.ms/api/v0.1/apps/grumpycoders/pcsx-redux-win64-cli/distribution_groups/public/releases/',
    method: 'appcenter',
    fileType: 'zip'
  },
  linux: {
    updateCatalog:
      'https://install.appcenter.ms/api/v0.1/apps/grumpycoders/pcsx-redux-linux64/distribution_groups/public/public_releases',
    updateInfoBase:
      'https://install.appcenter.ms/api/v0.1/apps/grumpycoders/pcsx-redux-linux64/distribution_groups/public/releases/',
    method: 'appcenter',
    fileType: 'zip'
  },
  darwin: {
    updateCatalog:
      'https://install.appcenter.ms/api/v0.1/apps/grumpycoders/pcsx-redux-macos/distribution_groups/public/public_releases',
    updateInfoBase:
      'https://install.appcenter.ms/api/v0.1/apps/grumpycoders/pcsx-redux-macos/distribution_groups/public/releases/',
    method: 'appcenter',
    fileType: 'dmg'
  }
}

let globalStorageUri

function isSupported() {
  let supported = false
  if (process.arch === 'x64') supported = true
  if (process.platform === 'darwin' && process.arch === 'arm64') {
    supported = true
  }
  return supported
}

function binaryPath() {
  switch (process.platform) {
    case 'win32':
      return vscode.Uri.joinPath(
        globalStorageUri,
        'pcsx-redux',
        'pcsx-redux.exe'
      ).fsPath
    case 'linux':
      return vscode.Uri.joinPath(
        globalStorageUri,
        'PCSX-Redux-HEAD-x86_64.AppImage'
      ).fsPath
    case 'darwin':
      return vscode.Uri.joinPath(
        globalStorageUri,
        'PCSX-Redux.app',
        'Contents',
        'MacOS',
        'PCSX-Redux'
      ).fsPath
  }
}

function checkLocalFile(filename) {
  return new Promise((resolve) => {
    fs.access(filename, fs.constants.F_OK, (err) => {
      resolve(!err)
    })
  })
}

exports.check = () => {
  const path = binaryPath()
  if (path === undefined) return Promise.resolve(false)
  return checkLocalFile(path)
}

exports.install = async () => {
  if (!isSupported()) {
    throw new Error(
      'Unsupported platform. You can still use PCSX-Redux by compiling it from source.'
    )
  }

  if (process.platform === 'win32') {
    const dllPath = 'C:\\Windows\\System32\\msvcp140_atomic_wait.dll'
    if (!await checkLocalFile(dllPath)) {
      const fullPath = path.join(os.tmpdir(), 'Microsoft.VCLibs.x64.14.00.Desktop.appx')
      downloader.downloadFile('https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx', fullPath)
      await exec(`powershell Add-AppxPackage ${fullPath}`)
    }
  }

  const updateInfoForPlatform = updateInfo[process.platform]
  const outputDir =
    process.platform === 'win32'
      ? vscode.Uri.joinPath(globalStorageUri, 'pcsx-redux').fsPath
      : globalStorageUri.fsPath

  return mkdirp(outputDir)
    .then(() => {
      return axios.request({
        method: 'get',
        url: updateInfoForPlatform.updateCatalog,
        responseType: 'stream'
      })
    })
    .then((response) => {
      return new Promise((resolve, reject) => {
        let highestId = -1
        response.data
          .on('close', () => {
            resolve(highestId)
          })
          .on('error', (err) => {
            reject(err)
          })
          .pipe(jsonStream.parse([true]))
          .on('data', (data) => {
            if (data.id > highestId) highestId = data.id
          })
      })
    })
    .then((updateId) => {
      return axios
        .request({
          method: 'get',
          url: updateInfoForPlatform.updateInfoBase + updateId,
          responseType: 'stream'
        })
        .then((response) => {
          return new Promise((resolve, reject) => {
            let downloadUrl
            response.data
              .on('close', () => {
                resolve(downloadUrl)
              })
              .on('error', (err) => {
                reject(err)
              })
              .pipe(jsonStream.parse(['download_url']))
              .on('data', (data) => {
                downloadUrl = data
              })
          })
        })
    })
    .then((downloadUrl) => {
      if (downloadUrl === undefined) {
        throw new Error('Invalid AppCenter catalog information.')
      }
      return downloader.downloadFile(
        downloadUrl,
        outputDir,
        updateInfoForPlatform.fileType === 'zip'
      )
    })
    .then((output) => {
      let mountPoint
      switch (process.platform) {
        case 'linux':
          return fs.chmod(
            path.join(outputDir, 'PCSX-Redux-HEAD-x86_64.AppImage'),
            0o775
          )
        case 'darwin':
          return dmgMount(outputDir)
            .then((mp) => {
              mountPoint = mp
              return copy(
                path.join(mountPoint, 'PCSX-Redux.app'),
                path.join(outputDir, 'PCSX-Redux.app'),
                { overwrite: true }
              )
            })
            .then(() => {
              return dmgUnmount(mountPoint)
            })
      }
      return Promise.resolve()
    })
}

exports.launch = async () => {
  let path = binaryPath()
  if (path === undefined || !(await checkLocalFile(path))) path = 'PCSX-Redux'
  const cwd = vscode.Uri.joinPath(
    globalStorageUri,
    'pcsx-redux-settings'
  ).fsPath
  await fs.mkdirp(cwd)
  const pcdrvOpts = []
  if (vscode.workspace.workspaceFolders) {
    pcdrvOpts.push('-pcdrv')
    pcdrvOpts.push('-pcdrvbase')
    pcdrvOpts.push(vscode.workspace.workspaceFolders[0].uri.fsPath)
  }
  return terminal.run(
    path,
    [
      '-stdout',
      '-lua_stdout',
      '-interpreter',
      '-debugger',
      '-gdb',
      '-portable',
      '-noupdate',
      ...pcdrvOpts
    ],
    { name: 'PCSX-Redux', cwd }
  )
}

exports.setGlobalStorageUri = (uri) => {
  globalStorageUri = uri
}