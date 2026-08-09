/**
 * @name Unauthorized Electron API Usage
 * @description Direct runtime usage of native Electron APIs bypasses Joplin's sanctioned plugin architecture.
 * @kind problem
 * @problem.severity warning
 * @id joplin/electron-api-usage
 */
import javascript

bindingset[moduleName]
predicate isElectronModule(string moduleName) {
  moduleName.regexpMatch("(node:)?electron(/(main|renderer|common))?")
}

predicate isElectronMember(DataFlow::Node node, string prop) {
  exists(string moduleName |
    isElectronModule(moduleName) and
    (
      node = DataFlow::moduleMember(moduleName, prop)
      or
      exists(DataFlow::CallNode requireCall |
        requireCall.getCalleeName() = "require" and
        requireCall.getArgument(0).getStringValue() = moduleName and
        node = requireCall.getAPropertyRead(prop)
      )
    )
  ) and
  not exists(ImportSpecifier specifier |
    (specifier.isTypeOnly() or specifier.getImportDeclaration().isTypeOnly()) and
    specifier.getImportedName() = prop and
    node.getFile() = specifier.getFile() and
    node.getLocation().getStartLine() = specifier.getLocation().getStartLine()
  ) and
  // Rule 16 exclusively owns Electron remote access.
  prop != "remote"
}

bindingset[prop]
predicate guidanceForElectronProperty(string prop, string msg) {
  prop = "BrowserWindow" and
  msg = "Use Joplin panels or dialogs instead of creating native Electron windows."
  or
  prop = "dialog" and
  msg = "Use `joplin.views.dialogs` instead of `electron.dialog`."
  or
  prop = "app" and
  msg = "Use supported Joplin APIs such as `joplin.plugins.dataDir()` instead of Electron application paths."
  or
  prop = "clipboard" and
  msg = "Use the `joplin.clipboard` API instead of `electron.clipboard`."
  or
  prop = "shell" and
  msg = "Use Joplin's supported link handling instead of `electron.shell`."
  or
  prop in ["ipcRenderer", "ipcMain"] and
  msg = "Direct Electron IPC bypasses Joplin's plugin messaging boundary."
  or
  prop = "screen" and
  msg = "Direct display enumeration through `electron.screen` is outside the Joplin plugin API."
  or
  prop in ["session", "webContents", "protocol", "net"] and
  msg = "This Electron networking or web-session API can bypass Joplin's managed application boundary."
  or
  prop in ["globalShortcut", "desktopCapturer"] and
  msg = "This Electron API can monitor global input or capture desktop content outside Joplin."
  or
  prop in ["safeStorage", "utilityProcess"] and
  msg = "This Electron API exposes privileged native storage or process capabilities outside the Joplin plugin API."
  or
  not prop in [
    "BrowserWindow", "dialog", "app", "clipboard", "shell", "ipcRenderer", "ipcMain", "screen",
    "session", "webContents", "protocol", "net", "globalShortcut", "desktopCapturer", "safeStorage",
    "utilityProcess"
  ] and
  msg = "Raw `electron." + prop + "` access is unsupported and must be reviewed for an equivalent Joplin API."
}

from DataFlow::Node node, string prop, string msg
where
  isElectronMember(node, prop) and
  guidanceForElectronProperty(prop, msg)
select node, "Unauthorized Native API Usage: The plugin accesses the runtime Electron API directly. " + msg
