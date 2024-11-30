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

  function checkRequiredTools (templateKey) {
    for (const tool of templates[templateKey].requiredTools) {
      if (!tools[tool] || !tools[tool].installed) {
        return false
      }
    }
    return true
  }

  function refreshTemplates () {
    for (const key of Object.keys(templates)) {
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
        document.getElementById('project-path').value = message.path
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
          const intro = document.createElement('h3')
          intro.textContent =
            'Fill in your project details above, then select a template category below, and finally select a template to create a new project. If the create button is disabled, you need to install the required tools first.'
          templatesDiv.appendChild(intro)
          const categories = {}
          for (const [key, template] of Object.entries(templates)) {
            if (!categories[template.category]) {
              categories[template.category] = []
            }
            categories[template.category].push(key)
          }
          const panels = document.createElement('vscode-panels')
          for (const [category, templateKeys] of Object.entries(categories)) {
            const panelTab = document.createElement('vscode-panel-tab')
            panelTab.textContent = category
            panels.appendChild(panelTab)
            templateKeys // Suppress unused variable warning
          }
          for (const [category, templateKeys] of Object.entries(categories)) {
            const panel = document.createElement('vscode-panel-view')
            const panelDiv = document.createElement('div')
            panelDiv.className = 'templatespanel'
            if (message.categories[category] !== undefined) {
              const categoryDescription = document.createElement('h3')
              categoryDescription.textContent =
                message.categories[category].description
              panelDiv.appendChild(categoryDescription)
            }
            for (const key of templateKeys) {
              const template = templates[key]
              const templateDiv = document.createElement('div')
              templateDiv.className = 'template'
              const templateName = document.createElement('h2')
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
                  vscode.postMessage({ command: 'openUrl', url: template.url })
                })
              } else {
                templateDocumentation.disabled = true
              }
              templateDiv.appendChild(templateDocumentation)
              const spaceTextNode0 = document.createTextNode('  ')
              templateDiv.appendChild(spaceTextNode0)
              const templateExamples = document.createElement('vscode-button')
              templateExamples.textContent = 'Examples'
              templateExamples.appearance = 'secondary'
              if (template.examples) {
                templateExamples.addEventListener('click', () => {
                  vscode.postMessage({
                    command: 'openUrl',
                    url: template.examples
                  })
                })
              } else {
                templateExamples.disabled = true
              }
              templateDiv.appendChild(templateExamples)
              const spaceTextNode1 = document.createTextNode('  ')
              templateDiv.appendChild(spaceTextNode1)
              const templateInstallRequiredTools =
                document.createElement('vscode-button')
              templateInstallRequiredTools.textContent =
                'Install required tools'
              templateInstallRequiredTools.appearance = 'secondary'
              templateInstallRequiredTools.addEventListener('click', () => {
                vscode.postMessage({
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
                vscode.postMessage({
                  command: 'installTools',
                  tools: [
                    ...template.recommendedTools,
                    ...template.requiredTools
                  ]
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
                vscode.postMessage({
                  command: 'createProjectFromTemplate',
                  template: key,
                  path: document.getElementById('project-path').value,
                  name: document.getElementById('project-name').value
                })
              })
              templateDiv.appendChild(templateCreate)
              const hr = document.createElement('hr')
              templateDiv.appendChild(hr)
              panelDiv.appendChild(templateDiv)
            }
            panel.appendChild(panelDiv)
            panels.appendChild(panel)
          }
          templatesDiv.appendChild(panels)
          templateView.appendChild(templatesDiv)
        }
        break
      case 'tools':
        {
          toolsView.innerHTML = ''
          if (requireReboot) {
            const rebootDiv1 = document.createElement('div')
            rebootDiv1.className = 'reboot'
            const rebootText1 = document.createElement('p')
            rebootText1.textContent =
              'Some tools require a reboot to work properly. Please reboot your system before resuming installing more tools.'
            rebootDiv1.appendChild(rebootText1)
            toolsView.appendChild(rebootDiv1)
            templateView.innerHTML = ''
            const rebootDiv2 = document.createElement('div')
            rebootDiv2.className = 'reboot'
            const rebootText2 = document.createElement('p')
            rebootText2.textContent =
              'Some tools require a reboot to work properly. Please reboot your system before resuming installing more tools.'
            rebootDiv2.appendChild(rebootText2)
            templateView.appendChild(rebootDiv2)
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
    document
      .getElementById('show-redux-settings')
      .addEventListener('click', () => {
        vscode.postMessage({ command: 'showReduxSettings' })
      })
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
    document
      .getElementById('restore-python-env')
      .addEventListener('click', () => {
        vscode.postMessage({ command: 'restorePythonEnv' })
      })
    document.getElementById('update-modules').addEventListener('click', () => {
      vscode.postMessage({ command: 'updateModules' })
    })
  })
})()
