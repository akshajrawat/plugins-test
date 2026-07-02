/**
 * @name Silent Backup Hijacking (Taint)
 * @description Detects data from an export module flowing into a network, child_process, or unauthorized file system sink.
 * @kind path-problem
 * @problem.severity error
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
  exists(DataFlow::MethodCallNode reg, DataFlow::SourceNode def, DataFlow::SourceNode propValue |
    isExportModuleRegistration(reg) and
    def = reg.getArgument(0).getALocalSource() and
    propValue = def.getAPropertyWrite(propName).getRhs().getALocalSource() and
    fn = propValue
  )
}

module ContextTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = any(DataFlow::FunctionNode fn | isExportModuleCallback(fn, _)).getParameter(0).getAPropertyRead("destPath")
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | isFileSystemDataSink(call.getArgument(1)) and sink = call.getArgument(0)) or
    exists(DataFlow::Node src | isFileCopy(src, sink))
  }
}
module ContextTaint = TaintTracking::Global<ContextTaintConfig>;

predicate isFileCopy(DataFlow::Node src, DataFlow::Node dest) {
  exists(DataFlow::CallNode call, string moduleName, string callee |
    (moduleName = "fs" or moduleName = "fs-extra" or moduleName = "node:fs" or moduleName = "node:fs/promises" or moduleName = "fs/promises") and
    call = DataFlow::moduleMember(moduleName, _).getACall() and
    callee = call.getCalleeName() and
    (callee = "copyFile" or callee = "copyFileSync" or callee = "copy" or callee = "copySync" or callee = "move" or callee = "moveSync" or callee = "rename" or callee = "renameSync") |
    src = call.getArgument(0) and
    dest = call.getArgument(1)
  )
}

module BackupHijackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn, string propName |
      isExportModuleCallback(fn, propName) |
      (propName = "onInit" and source = fn.getParameter(0)) or
      (propName = "onClose" and source = fn.getParameter(0)) or
      (propName = "onProcessItem" and (source = fn.getParameter(0) or source = fn.getParameter(2))) or
      (propName = "onProcessResource" and (source = fn.getParameter(0) or source = fn.getParameter(1) or source = fn.getParameter(2)))
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink) or
    isCommandExecutionSink(sink) or
    (
      isFileSystemDataSink(sink) and
      exists(DataFlow::CallNode call | call.getArgument(1) = sink |
        not ContextTaint::flow(_, call.getArgument(0))
      )
    ) or
    exists(DataFlow::Node dest |
      isFileCopy(sink, dest) and
      not ContextTaint::flow(_, dest)
    )
  }
}

module BackupHijacking = TaintTracking::Global<BackupHijackingConfig>;
import BackupHijacking::PathGraph

from BackupHijacking::PathNode source, BackupHijacking::PathNode sink
where BackupHijacking::flowPath(source, sink)
select sink.getNode(), source, sink, "[High Confidence] Backup Hijacking Alert: Export data is confirmed flowing into a network request, terminal command, or unauthorized file path instead of the legitimate export destination."
