const vscode = require('vscode')
const fs = require('node:fs')
const Axios = require('axios').Axios
const stream = require('node:stream')
const util = require('node:util')
const finished = util.promisify(stream.finished)
const axios = new Axios({})
const { mkdirp } = require('fs-extra')
const path = require('path')
const unzipper = require('unzipper')

exports.downloadFile = async (url, output, unzip) => {
  let writer
  let progressResolver
  let progressReporter
  return mkdirp(path.dirname(output))
    .then(() => {
      if (!unzip) writer = fs.createWriteStream(output)
      vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'Download in progress...',
          cancellable: true
        },
        (progress) => {
          progress.report({ increment: 0 })
          progressReporter = progress
          return new Promise((resolve) => {
            progressResolver = resolve
          })
        }
      )

      return axios.request({
        method: 'get',
        url,
        responseType: 'stream',
        onDownloadProgress: (progressEvent) => {
          const percentCompleted = Math.floor(
            (progressEvent.loaded * 100) / progressEvent.total
          )
          progressReporter.report({ increment: percentCompleted })
        }
      })
    })
    .then((response) => {
      if (unzip) {
        progressReporter.report({ increment: 0, message: 'Decompressing...' })
        return new Promise((resolve, reject) => {
          response.data
            .pipe(unzipper.Extract({ path: output }))
            .on('close', () => {
              resolve(output)
            })
            .on('error', (err) => {
              reject(err)
            })
        })
      } else {
        response.data.pipe(writer)
        return finished(writer).then(() => { return Promise.resolve(output) })
      }
    })
    .then(() => {
      progressResolver()
    }).catch((err) => {
      progressResolver()
      throw err
    })
}
