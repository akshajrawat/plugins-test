/**
 * @name Silent Backup Hijacking (Structural)
 * @description Detects registering an export module and making a network or file write call inside callbacks.
 * @kind problem
 * @problem.severity warning
 * @tags security joplin-plugin backup-hijacking-structural
 * @id js/joplin/backup-hijacking-structural
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isExportModuleRegistration(DataFlow::MethodCallNode reg) {
  reg.getMethodName() = "registerExportModule" and
  reg.getReceiver().getALocalSource() = Joplin::interop()
}

predicate isExportModuleCallbackAST(Function fn) {
  exists(DataFlow::MethodCallNode reg, Expr def |
    isExportModuleRegistration(reg) and
    def = reg.getArgument(0).getALocalSource().asExpr() and
    fn.getParent*() = def
  )
}

module ContextTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Function fn | isExportModuleCallbackAST(fn) and source = DataFlow::parameterNode(fn.getParameter(0)))
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | isFileSystemPathSink(call.getArgument(0)) and sink = call.getArgument(0))
  }
}
module ContextTaint = TaintTracking::Global<ContextTaintConfig>;

from DataFlow::CallNode dangerousCall
where
  isExportModuleCallbackAST(dangerousCall.getEnclosingFunction()) and
  (
    isNetworkExfiltrationCall(dangerousCall) or
    isCommandExecutionSink(dangerousCall.getAnArgument()) or
    (
      isFileSystemPathSink(dangerousCall.getArgument(0)) and
      not ContextTaint::flow(_, dangerousCall.getArgument(0))
    )
  )
select dangerousCall, "[Low Confidence] Backup Hijacking Indicator: A network, terminal execution, or file-write call exists inside an export callback, but direct data flow isn't confirmed by taint tracking. \\n**Reviewer Action:** Manual trace required. Verify if the execution/network call is legitimately part of the export process."
