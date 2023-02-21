'use strict'

/* global acquireVsCodeApi, window, document */

import {
  provideVSCodeDesignSystem,
  allComponents
} from '../node_modules/@vscode/webview-ui-toolkit/dist/toolkit.min.js'
;(function () {
  provideVSCodeDesignSystem().register(allComponents)
  const vscode = acquireVsCodeApi()

  window.addEventListener('message', (event) => {
    const message = event.data
    switch (message.command) {
      case 'tools':
        {
          const templateView = document.getElementById('templates-view')
          const toolsView = document.getElementById('tools-view')
          templateView.innerHTML = ''
          toolsView.innerHTML = ''
          const toolsDiv = document.createElement('div')
          toolsView.appendChild(toolsDiv)
          for (const [key, tool] of Object.entries(message.tools)) {
            if (tool.type === 'internal') continue
            const toolDiv = document.createElement('div')
            toolDiv.className = 'tool'
            const toolName = document.createElement('h3')
            toolName.textContent = tool.name
            toolDiv.appendChild(toolName)
            const toolDescription = document.createElement('p')
            toolDescription.textContent = tool.description
            toolDiv.appendChild(toolDescription)
            const toolButton = document.createElement('vscode-button')
            if (tool.installed) {
              toolButton.textContent = 'Already installed'
              toolButton.disabled = tool.installed
              toolButton.appearance = 'secondary'
            } else {
              toolButton.textContent = 'Install'
            }
            toolButton.addEventListener('click', () => {
              vscode.postMessage({ command: 'installTool', tool: key })
            })
            toolDiv.appendChild(toolButton)
            const hr = document.createElement('hr')
            toolDiv.appendChild(hr)
            toolsDiv.appendChild(toolDiv)
          }
        }
        break
    }
  })

  window.addEventListener('load', () => {
    vscode.postMessage({ command: 'refreshTools' })
    document.getElementById('refresh').addEventListener('click', () => {
      const templateView = document.getElementById('templates-view')
      const toolsView = document.getElementById('tools-view')
      templateView.innerHTML = ''
      toolsView.innerHTML = ''
      const spinner1 = document.createElement('vscode-progress-ring')
      const spinner2 = document.createElement('vscode-progress-ring')
      templateView.appendChild(spinner1)
      toolsView.appendChild(spinner2)
      vscode.postMessage({ command: 'refreshTools' })
    })
  })
})()
