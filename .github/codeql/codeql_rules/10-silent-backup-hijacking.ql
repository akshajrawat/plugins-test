/**
 * @name Silent Backup Hijacking (Taint)
 * @description Detects data from an export module flowing into a network, child_process, or unauthorized file system sink.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin backup-hijacking
 * @id js/joplin/backup-hijacking
 */
import javascript
import JoplinSources
import JoplinSinks
import JoplinLinks

predicate isExportModuleRegistration(DataFlow::MethodCallNode reg) {
  reg.getMethodName() = "registerExportModule" and
  reg.getReceiver().getALocalSource() = Joplin::interop()
}

predicate isExportModuleCallback(DataFlow::FunctionNode fn, string propName) {
  exists(DataFlow::MethodCallNode reg, ObjectExpr def, Property prop |
    isExportModuleRegistration(reg) and
    def = reg.getArgument(0).getALocalSource().asExpr() and
    prop = def.getAProperty() and
    propName = prop.getName() and
    fn.asExpr() = prop.getInit()
  )
}

module ContextTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = any(DataFlow::FunctionNode fn | isExportModuleCallback(fn, _)).getParameter(0)
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | JoplinSinks::isFileSystemDataSink(call.getArgument(1)) and sink = call.getArgument(0))
  }
}
module ContextTaint = TaintTracking::Global<ContextTaintConfig>;

module BackupHijackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn, string propName |
      isExportModuleCallback(fn, propName) |
      (propName = "onProcessItem" and source = fn.getParameter(2)) or
      (propName = "onProcessResource" and (source = fn.getParameter(1) or source = fn.getParameter(2))) or
      ((propName = "onInit" or propName = "onClose" or propName = "onExec") and source = fn.getParameter(0))
    )
  }

  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isNetworkExfiltrationSink(sink) or
    JoplinSinks::isCommandExecutionSink(sink) or
    (
      JoplinSinks::isFileSystemDataSink(sink) and
      exists(DataFlow::CallNode call | call.getArgument(1) = sink |
        not ContextTaint::flow(_, call.getArgument(0))
      )
    )
  }
}

module BackupHijacking = TaintTracking::Global<BackupHijackingConfig>;
import BackupHijacking::PathGraph

from BackupHijacking::PathNode source, BackupHijacking::PathNode sink
where BackupHijacking::flowPath(source, sink)
select sink.getNode(), source, sink, "High Confidence Backup Hijacking: Export data flows into a network, command execution, or unauthorized file system sink. \n" +
  "Reviewer: verify flagged data is actual note/resource content, not just context metadata."
