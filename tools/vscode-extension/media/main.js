'use strict'

import { provideVSCodeDesignSystem, allComponents } from '../node_modules/@vscode/webview-ui-toolkit/dist/toolkit.min.js';

(function () {
  provideVSCodeDesignSystem().register(allComponents)
  const vscode = acquireVsCodeApi()

  window.addEventListener('message', (event) => {
    const message = event.data
    switch (message.command) {
    }
  })

  window.addEventListener('load', () => {
  })
})()
