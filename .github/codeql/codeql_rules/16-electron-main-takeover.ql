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
  exists(string moduleName |
    remoteAccess = DataFlow::moduleImport(moduleName) and
    moduleName.regexpMatch("@electron/remote(/.*)?")
  ) or
  remoteAccess = DataFlow::moduleMember("electron", "remote")
select remoteAccess, "Critical Violation (Electron Remote Access): The plugin imports or accesses `@electron/remote` or `electron.remote`. If remote access is available, it can bypass Joplin's normal plugin API boundary and expose privileged Electron main-process capabilities. This unsupported access must be removed before publishing."
