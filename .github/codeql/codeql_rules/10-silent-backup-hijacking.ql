/**
 * @name Silent Backup Hijacking
 * @description Detects registering an export module and silently stealing data via network or file writes inside callbacks.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin backup-hijacking
 * @id js/joplin/backup-hijacking
 */
import javascript
import JoplinSources

/**
 * Holds if `reg` is a call to joplin.interop.registerExportModule().
 */
predicate isExportModuleRegistration(DataFlow::MethodCallNode reg) {
  reg.getMethodName() = "registerExportModule" and
  reg.getReceiver().getALocalSource() = Joplin::interop()
}

/**
 * Holds if `call` sends data over the network.
 */
predicate sendsToNetwork(DataFlow::CallNode call) {
  call.getCalleeName() = "fetch" or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", _) or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("https", "request") or
  call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("http", "request")
}

/**
 * Holds if `call` writes to the file system.
 */
predicate writesToFileSystem(DataFlow::CallNode call) {
  call.getCalleeName() = "writeFile" or
  call.getCalleeName() = "writeFileSync" or
  call.getCalleeName() = "appendFile"
}

/**
 * Holds if `fn` is a callback function nested inside a registerExportModule argument.
 */
predicate isExportModuleCallback(Function fn) {
  exists(DataFlow::MethodCallNode reg |
    isExportModuleRegistration(reg) and
    fn.getEnclosingStmt().getParent*() = reg.asExpr().getEnclosingStmt()
  )
  or
  exists(DataFlow::MethodCallNode reg, Expr argExpr |
    isExportModuleRegistration(reg) and
    argExpr = reg.getArgument(0).asExpr() and
    fn.getEnclosingStmt().getParent*() = argExpr.getEnclosingStmt()
  )
}

from DataFlow::CallNode dangerousCall, DataFlow::MethodCallNode reg
where
  isExportModuleRegistration(reg) and
  (sendsToNetwork(dangerousCall) or writesToFileSystem(dangerousCall)) and
  isExportModuleCallback(dangerousCall.getEnclosingFunction())
select dangerousCall, "Silent Backup Hijacking: network or file write inside a registerExportModule callback. Requires human review."
