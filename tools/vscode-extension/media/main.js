'use strict'

/* global acquireVsCodeApi, window, document */

import {
  provideVSCodeDesignSystem,
  allComponents
} from '../node_modules/@vscode/webview-ui-toolkit/dist/toolkit.min.js'
;(function () {
  provideVSCodeDesignSystem().register(allComponents)
  const vscode = acquireVsCodeApi()
  const templateView = document.getElementById('templates-view')
  const toolsView = document.getElementById('tools-view')

  let requireReboot = false
  let tools = {}
  let templates

  function checkRequiredTools(templateKey) {
    for (const tool of templates[templateKey].requiredTools) {
      if (!tools[tool] || !tools[tool].installed) {
        return false
      }
    }
    return true
  }

  function refreshTemplates() {
    for (const [key, template] of Object.entries(templates)) {
      const templateCreate = document.getElementById('create-' + key)
      if (templateCreate) templateCreate.disabled = !checkRequiredTools(key)
    }
  }

  window.addEventListener('message', (event) => {
    const message = event.data
    switch (message.command) {
      case 'requireReboot':
        requireReboot = true
        break
      case 'projectDirectory':
        document.getElementById('project-path').value = message.fsPath
        break
      case 'templates':
        {
          vscode.postMessage({ command: 'requestHomeDirectory' })
          templates = message.templates
          templateView.innerHTML = ''
          const templatesDiv = document.createElement('div')
          const nameInput = document.createElement('vscode-text-field')
          nameInput.id = 'project-name'
          nameInput.placeholder = 'Name'
          nameInput.textContent = 'Project name'
          templatesDiv.appendChild(nameInput)
          const hr1 = document.createElement('hr')
          templatesDiv.appendChild(hr1)
          const pathInput = document.createElement('vscode-text-field')
          pathInput.id = 'project-path'
          pathInput.placeholder = 'Path'
          pathInput.textContent = "Project's parent directory"
          pathInput.readonly = true
          templatesDiv.appendChild(pathInput)
          const br = document.createElement('br')
          templatesDiv.appendChild(br)
          const browseButton = document.createElement('vscode-button')
          browseButton.textContent = 'Browse'
          browseButton.appearance = 'secondary'
          browseButton.addEventListener('click', () => {
            vscode.postMessage({ command: 'browseForProjectDirectory' })
          })
          templatesDiv.appendChild(browseButton)
          const hr2 = document.createElement('hr')
          templatesDiv.appendChild(hr2)
          for (const [key, template] of Object.entries(templates)) {
            const templateDiv = document.createElement('div')
            templateDiv.className = 'template'
            const templateName = document.createElement('h3')
            templateName.textContent = template.name
            templateDiv.appendChild(templateName)
            const templateDescription = document.createElement('p')
            templateDescription.textContent = template.description
            templateDiv.appendChild(templateDescription)
            const templateDocumentation =
              document.createElement('vscode-button')
            templateDocumentation.textContent = 'Documentation'
            templateDocumentation.appearance = 'secondary'
            if (template.url) {
              templateDocumentation.addEventListener('click', () => {
                vscode.postmessage({ command: 'openurl', url: template.url })
              })
            } else {
              templateDocumentation.disabled = true
            }
            templateDiv.appendChild(templateDocumentation)
            const spaceTextNode1 = document.createTextNode('  ')
            templateDiv.appendChild(spaceTextNode1)
            const templateInstallRequiredTools =
              document.createElement('vscode-button')
            templateInstallRequiredTools.textContent = 'Install required tools'
            templateInstallRequiredTools.appearance = 'secondary'
            templateInstallRequiredTools.addEventListener('click', () => {
              vscode.postmessage({
                command: 'installTools',
                tools: template.requiredTools
              })
            })
            templateDiv.appendChild(templateInstallRequiredTools)
            const spaceTextNode2 = document.createTextNode('  ')
            templateDiv.appendChild(spaceTextNode2)
            const templateInstallRecommendedTools =
              document.createElement('vscode-button')
            templateInstallRecommendedTools.textContent =
              'Install recommended tools'
            templateInstallRecommendedTools.appearance = 'secondary'
            templateInstallRecommendedTools.addEventListener('click', () => {
              vscode.postmessage({
                command: 'installTools',
                tools: template.recommendedTools + template.requiredTools
              })
            })
            templateDiv.appendChild(templateInstallRecommendedTools)
            const spaceTextNode3 = document.createTextNode('  ')
            templateDiv.appendChild(spaceTextNode3)
            const templateCreate = document.createElement('vscode-button')
            templateCreate.textContent = 'Create'
            templateCreate.id = 'create-' + key
            templateCreate.disabled = true
            templateCreate.addEventListener('click', () => {
              vscode.postmessage({
                command: 'createProjectFromTemplate',
                template: key,
                path: document.getElementById('project-path').value,
                name: document.getElementById('project-name').value
              })
            })
            templateDiv.appendChild(templateCreate)
            const hr = document.createElement('hr')
            templateDiv.appendChild(hr)
            templatesDiv.appendChild(templateDiv)
          }
          templateView.appendChild(templatesDiv)
        }
        break
      case 'tools':
        {
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
            templateView.innerHTML = ''
            templateView.appendChild(rebootDiv)
            break
          }
          const toolsDiv = document.createElement('div')
          toolsView.appendChild(toolsDiv)
          tools = message.tools
          refreshTemplates()
          for (const [key, tool] of Object.entries(tools)) {
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
            if (tool.homepage) {
              homepageButton.addEventListener('click', () => {
                vscode.postMessage({ command: 'openUrl', url: tool.homepage })
              })
            } else {
              homepageButton.disabled = true
            }
            toolDiv.appendChild(homepageButton)
            const spaceTextNode = document.createTextNode('  ')
            toolDiv.appendChild(spaceTextNode)
            const toolButton = document.createElement('vscode-button')
            if (tool.installed) {
              if (tool.type === 'archive') {
                toolButton.textContent = 'Download again'
              } else {
                toolButton.textContent = 'Install again'
              }
            } else {
              if (tool.type === 'archive') {
                toolButton.textContent = 'Download'
              } else {
                toolButton.textContent = 'Install'
              }
            }
            toolButton.addEventListener('click', () => {
              toolsView.innerHTML = ''
              const spinner = document.createElement('vscode-progress-ring')
              toolsView.appendChild(spinner)
              vscode.postMessage({
                command: 'installTools',
                tools: [key],
                force: true
              })
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
    vscode.postMessage({ command: 'getTemplates' })
    document.getElementById('refresh').addEventListener('click', () => {
      toolsView.innerHTML = ''
      const spinner = document.createElement('vscode-progress-ring')
      toolsView.appendChild(spinner)
      vscode.postMessage({ command: 'refreshTools' })
    })
    document.getElementById('launch-redux').addEventListener('click', () => {
      vscode.postMessage({ command: 'launchRedux' })
    })
    document.getElementById('restore-psyq').addEventListener('click', () => {
      vscode.postMessage({ command: 'restorePsyq' })
    })
  })
})()
