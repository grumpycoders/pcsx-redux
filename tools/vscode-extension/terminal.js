'use strict'

const vscode = require('vscode')
const which = require('which')

exports.run = async function (binary, args, options) {
  if (process.platform === 'win32') {
    args = args.join(' ')
  }

  if (options === undefined) options = {}
  let name = options.name
  if (name === undefined) name = 'PSX.Dev'
  const message = options.message
  const terminal = vscode.window.createTerminal({
    shellPath: await which(binary, { nothrow: true }),
    shellArgs: args,
    name,
    message,
    cwd: options.cwd
  })
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
