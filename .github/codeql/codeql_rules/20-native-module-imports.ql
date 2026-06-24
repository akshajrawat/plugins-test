/**
 * @name Native Module Imports
 * @description Bypassing joplin.require to gain host access.
 * @kind problem
 * @problem.severity error
 * @id joplin/native-module-imports
 */
import javascript

from DataFlow::CallNode requireCall, string moduleName
where
  requireCall.getCalleeName() = "require" and
  not requireCall.getReceiver().getALocalSource().toString() = "joplin" and
  moduleName = requireCall.getArgument(0).getStringValue() and
  (moduleName = "child_process" or moduleName = "net" or moduleName = "os" or moduleName = "dgram" or moduleName = "fs")
select requireCall, "Direct import of native module bypasses Joplin API restrictions."
