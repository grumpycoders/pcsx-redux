'use strict'

/* global acquireVsCodeApi, window, document */

import {
  provideVSCodeDesignSystem,
  allComponents
} from '../node_modules/@vscode/webview-ui-toolkit/dist/toolkit.min.js'
;(function () {
  provideVSCodeDesignSystem().register(allComponents)
  const vscode = acquireVsCodeApi()

  let requireReboot = false

  window.addEventListener('message', (event) => {
    const message = event.data
    switch (message.command) {
      case 'requireReboot':
        requireReboot = true
        break
      case 'tools':
        {
          const templateView = document.getElementById('templates-view')
          const toolsView = document.getElementById('tools-view')
          templateView.innerHTML = ''
          toolsView.innerHTML = ''
          if (requireReboot) {
            const rebootDiv = document.createElement('div')
            rebootDiv.className = 'reboot'
            const rebootText = document.createElement('p')
            rebootText.textContent =
              'Some tools require a reboot to work properly. Please reboot your system before resuming installing more tools.'
            rebootDiv.appendChild(rebootText)
            templateView.appendChild(rebootDiv)
            toolsView.appendChild(rebootDiv)
          }
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
            const homepageButton = document.createElement('vscode-button')
            homepageButton.textContent = 'Homepage'
            homepageButton.appearance = 'secondary'
            homepageButton.addEventListener('click', () => {
              vscode.postMessage({ command: 'openUrl', url: tool.homepage })
            })
            toolDiv.appendChild(homepageButton)
            const spaceTextNode = document.createTextNode('  ')
            toolDiv.appendChild(spaceTextNode)
            const toolButton = document.createElement('vscode-button')
            if (tool.installed) {
              toolButton.textContent = 'Already installed'
              toolButton.disabled = tool.installed
            } else {
              toolButton.textContent = 'Install'
            }
            toolButton.addEventListener('click', () => {
              vscode.postMessage({ command: 'installTools', tools: [key] })
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
