'use strict'

const vscode = require('vscode')

exports.run = function (binary, args) {
  if (process.platform === 'win32') {
    args = args.join(' ')
  }
  const terminal = vscode.window.createTerminal('PSX.Dev', binary, args)
  terminal.show()
  let resolver
  let rejecter
  const promise = new Promise((resolve, reject) => {
    resolver = resolve
    rejecter = reject
  })
  vscode.window.onDidCloseTerminal((t) => {
    if (t === terminal) {
      if (t.exitStatus.code === 0) {
        resolver()
      } else {
        rejecter()
      }
    }
  })
  return promise
}
