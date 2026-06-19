/**
 * @name Electron Main Process Takeover
 * @description Gaining direct access to the main Electron process to control the app window or bypass renderer restrictions.
 * @kind problem
 * @problem.severity error
 * @id joplin/electron-main-takeover
 */
import javascript

from DataFlow::CallNode requireCall
where
  requireCall.getCalleeName() = "require" and
  requireCall.getArgument(0).getStringValue() = "@electron/remote"
select requireCall, "Usage of @electron/remote is prohibited as it allows main process takeover."
