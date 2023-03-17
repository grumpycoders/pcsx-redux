'use strict'

const vscode = require('vscode')

exports.notify = async function (title, message) {
  let progressReporter
  let progressResolver

  const notificationDisplayed = new Promise((notificationReady) => {
    vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title,
        cancellable: true
      },
      (progress) => {
        progress.report({ message, increment: 0 })
        progressReporter = progress
        return new Promise((resolve) => {
          notificationReady()
          progressResolver = resolve
        })
      }
    )
  })
  await notificationDisplayed

  return { progressReporter, progressResolver }
}
