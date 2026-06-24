/**
 * @name Unauthorized Electron API Usage
 * @description Direct usage of native Electron APIs bypasses Joplin's sanctioned plugin architecture.
 * @kind problem
 * @problem.severity warning
 * @id joplin/electron-api-usage
 */
import javascript

from DataFlow::Node node, string msg
where
  // Generic electron import
  (
    node = DataFlow::moduleImport("electron") and
    msg = "Direct usage of the 'electron' module bypasses Joplin's plugin APIs."
  )
  or
  // Specific property accesses
  exists(string prop |
    node = DataFlow::moduleMember("electron", prop) and
    (
      prop = "BrowserWindow" and msg = "Use joplin.views.panels / joplin.views.dialogs instead of electron.BrowserWindow." or
      prop = "dialog" and msg = "Use joplin.views.dialogs instead of electron.dialog." or
      prop = "app" and msg = "Use joplin.plugins.dataDir instead of electron.app paths." or
      prop = "clipboard" and msg = "Use joplin.clipboard API instead of electron.clipboard." or
      prop = "shell" and msg = "Use <a target='_blank'> or Joplin's link handling instead of electron.shell." or
      prop = "ipcRenderer" and msg = "Direct IPC channel access bypasses Joplin's plugin messaging entirely — should not be used at all." or
      prop = "ipcMain" and msg = "Direct IPC channel access bypasses Joplin's plugin messaging entirely — should not be used at all." or
      prop = "screen" and msg = "Usage of electron.screen bypasses Joplin's plugin APIs."
    )
  )
select node, msg
