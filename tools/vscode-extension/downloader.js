const fs = require('fs-extra')
const Axios = require('axios').Axios
const stream = require('node:stream')
const util = require('node:util')
const finished = util.promisify(stream.finished)
const axios = new Axios({})
const path = require('path')
const unzipper = require('unzipper')
const progressNotification = require('./progressnotification.js')

exports.downloadFile = async (url, output, unzip) => {
  let writer
  const { progressReporter, progressResolver } =
    await progressNotification.notify('Download in progress', 'Downloading...')
  await fs.mkdirp(path.dirname(output))
  if (!unzip) writer = fs.createWriteStream(output)

  return axios
    .request({
      method: 'get',
      url,
      responseType: 'stream',
      onDownloadProgress: (progressEvent) => {
        const percentCompleted = Math.floor(
          (progressEvent.loaded * 100) / progressEvent.total
        )

        if (percentCompleted >= 99.9 && unzip) {
          progressReporter.report({
            increment: 0,
            message: 'Decompressing...'
          })
        } else {
          progressReporter.report({ increment: percentCompleted })
        }
      }
    })
    .then((response) => {
      if (unzip) {
        return new Promise((resolve, reject) => {
          response.data
            .pipe(unzipper.Extract({ path: output }))
            .on('close', () => resolve(output))
            .on('error', (err) => reject(err))
        })
      } else {
        response.data.pipe(writer)
        return finished(writer).then(() => Promise.resolve(output))
      }
    })
    .then(() => progressResolver())
    .catch((err) => {
      if (progressResolver) progressResolver()
      throw err
    })
}
