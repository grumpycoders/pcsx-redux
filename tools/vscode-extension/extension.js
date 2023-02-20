'use strict'

const vscode = require('vscode')

class PSXDevPanel {
  static currentPanel = undefined

  static createOrShow (extensionUri) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined
    // If we already have a panel, show it.
    if (PSXDevPanel.currentPanel) {
      PSXDevPanel.currentPanel._panel.reveal(column)
      return
    }
    // Otherwise, create a new panel.
    const panel = vscode.window.createWebviewPanel(
      PSXDevPanel.viewType,
      'PSX.Dev',
      column || vscode.ViewColumn.One,
      getWebviewOptions(extensionUri)
    )
    PSXDevPanel.currentPanel = new PSXDevPanel(panel, extensionUri)
  }

  static revive (panel, extensionUri) {
    PSXDevPanel.currentPanel = new PSXDevPanel(panel, extensionUri)
  }

  constructor (panel, extensionUri) {
    this._disposables = []
    this._panel = panel
    this._extensionUri = extensionUri
    // Set the webview's initial html content
    this._update()
    // Listen for when the panel is disposed
    // This happens when the user closes the panel or when the panel is closed programmatically
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables)
    // Update the content based on view changes
    this._panel.onDidChangeViewState(
      () => {
        if (this._panel.visible) {
          this._update()
        }
      },
      null,
      this._disposables
    )
    // Handle messages from the webview
    this._panel.webview.onDidReceiveMessage(
      (message) => {
        switch (message.command) {
          case 'alert':
            vscode.window.showErrorMessage(message.text)
        }
      },
      null,
      this._disposables
    )
  }

  sendAlert (text) {
    this._panel.webview.postMessage({ command: 'alert', text })
  }

  dispose () {
    PSXDevPanel.currentPanel = undefined
    // Clean up our resources
    this._panel.dispose()
    while (this._disposables.length) {
      const x = this._disposables.pop()
      if (x) {
        x.dispose()
      }
    }
  }

  _update () {
    const webview = this._panel.webview
    webview.html = this._getHtmlForWebview(webview)
  }

  _getHtmlForWebview (webview) {
    const scriptPathOnDisk = vscode.Uri.joinPath(
      this._extensionUri,
      'media',
      'main.js'
    )
    const scriptUri = webview.asWebviewUri(scriptPathOnDisk)
    const nonce = getNonce()
    return `<!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">

        <!--
          Use a content security policy to only allow loading images from https or from our extension directory,
          and only allow scripts that have a specific nonce.
        -->
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; img-src ${webview.cspSource} https:; script-src 'nonce-${nonce}';">

        <meta name="viewport" content="width=device-width, initial-scale=1.0">

        <title>PSX.Dev</title>
      </head>
      <body>
        <vscode-panels>
          <vscode-panel-tab id="welcome-tab">WELCOME</vscode-panel-tab>
          <vscode-panel-tab id="templates-tab">TEMPLATES</vscode-panel-tab>
          <vscode-panel-tab id="tools-tab">TOOLS</vscode-panel-tab>
          <vscode-panel-view id="welcome-view">
            <div>
              <h1>Welcome to the PSX.Dev VSCode extension</h1>
              <p>Using this extension, you can install and maintain the necessary tools to develop PS1 software, and create projects based on templates. Click on the tabs above to get started. </p>
              <p>You can always use the commands in the Command Palette (Ctrl+Shift+P) to access this panel again. Search for the <b>PSX.Dev: Show Panel</b> command.</p>
              <p>You can access more information about PlayStation 1 development on the <a href="https://psx.dev/" target="_blank">PSX.Dev website</a>. Please do not hesitate to join the Discord server!</p>
            </div>
          </vscode-panel-view>
          <vscode-panel-view id="templates-view">Templates</vscode-panel-view>
          <vscode-panel-view id="tools-view">Tools</vscode-panel-view>
        </vscode-panels>
        <script type="module" nonce="${nonce}" src="${scriptUri}"></script>
      </body>
      </html>`
  }
}

PSXDevPanel.viewType = 'psxDev'

function activate (context) {
  context.subscriptions.push(
    vscode.commands.registerCommand('psxDev.showPanel', () => {
      PSXDevPanel.createOrShow(context.extensionUri)
    })
  )
  context.subscriptions.push(
    vscode.commands.registerCommand('psxDev.hello', () => {
      const currentPanel = PSXDevPanel.currentPanel
      if (currentPanel) {
        currentPanel.sendAlert('Hello')
      }
    })
  )

  // Make sure we register a serializer in activation event
  vscode.window.registerWebviewPanelSerializer(PSXDevPanel.viewType, {
    async deserializeWebviewPanel (webviewPanel, state) {
      console.log(`Got state: ${state}`)
      // Reset the webview options so we use latest uri for `localResourceRoots`.
      webviewPanel.webview.options = getWebviewOptions(context.extensionUri)
      PSXDevPanel.revive(webviewPanel, context.extensionUri)
    }
  })
}

function getWebviewOptions (extensionUri) {
  return {
    enableScripts: true,
    localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media'), vscode.Uri.joinPath(extensionUri, 'node_modules')]
  }
}

function getNonce () {
  let text = ''
  const possible =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length))
  }
  return text
}

// This method is called when your extension is deactivated
function deactivate () {}

module.exports = {
  activate,
  deactivate
}
