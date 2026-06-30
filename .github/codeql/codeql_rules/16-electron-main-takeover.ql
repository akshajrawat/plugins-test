/**
 * @name Electron Main Process Takeover
 * @description Gaining direct access to the main Electron process to control the app window or bypass renderer restrictions.
 * @kind problem
 * @problem.severity error
 * @id joplin/electron-main-takeover
 */
import javascript

from DataFlow::Node remoteAccess
where
  remoteAccess = DataFlow::moduleImport("@electron/remote") or
  remoteAccess = DataFlow::moduleMember("electron", "remote")
select remoteAccess, "Critical Violation (Main Process Takeover): The plugin is attempting to import or require `@electron/remote` or `electron.remote`. \\n**Reviewer Action:** This completely bypasses the plugin sandbox and grants full control over the Joplin application window and the OS. This must be strictly prohibited and removed before publishing."
