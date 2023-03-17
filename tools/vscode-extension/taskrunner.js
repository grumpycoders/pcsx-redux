'use strict'

const vscode = require('vscode')

exports.run = async function (name) {
  const tasks = await vscode.tasks.fetchTasks()
  const task = tasks.find((task) => task.name === name)

  if (task === undefined) {
    throw new Error(`No task named '${name}'`)
  }

  return Promise.resolve(vscode.tasks.executeTask(task))
}
