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
select remoteAccess, "Usage of electron.remote is prohibited as it allows main process takeover."
