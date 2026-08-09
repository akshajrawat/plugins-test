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

predicate isExportModuleCallbackName(string propName) {
  propName = ["onInit", "onProcessItem", "onProcessResource", "onClose"]
}

predicate isExportModuleDefinition(DataFlow::MethodCallNode reg, DataFlow::SourceNode def) {
  def = reg.getArgument(0).getALocalSource()
  or
  exists(DataFlow::CallNode factoryCall, DataFlow::FunctionNode factory |
    factoryCall = reg.getArgument(0).getALocalSource() and
    factory = factoryCall.getCalleeNode().getAFunctionValue() and
    def = factory.getAReturn().getALocalSource()
  )
}

predicate isExportModuleCallback(DataFlow::FunctionNode fn, string propName) {
  exists(DataFlow::MethodCallNode reg, DataFlow::SourceNode def, DataFlow::SourceNode propValue |
    isExportModuleRegistration(reg) and
    isExportModuleCallbackName(propName) and
    isExportModuleDefinition(reg, def) and
    propValue = def.getAPropertyWrite(propName).getRhs().getALocalSource() and
    fn = propValue
  )
  or
  exists(DataFlow::MethodCallNode reg, DataFlow::NewNode instance, DataFlow::ClassNode cls |
    isExportModuleRegistration(reg) and
    isExportModuleCallbackName(propName) and
    instance = reg.getArgument(0).getALocalSource() and
    cls = instance.getCalleeNode().getALocalSource() and
    fn = cls.getInstanceMethod(propName)
  )
}

module ContextTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn, string propName |
      isExportModuleCallback(fn, propName) and
      source = fn.getParameter(0).getAPropertyRead("destPath")
    )
  }
  predicate isSink(DataFlow::Node sink) {
    sink = any(FileSystemWriteAccess access).getAPathArgument() or
    exists(DataFlow::Node data | isFileWrite(sink, data)) or
    exists(DataFlow::MethodCallNode call |
      isJoplinFsExtraCall(call) and
      call.getMethodName() in [
        "writeFile", "writeFileSync", "appendFile", "appendFileSync", "outputFile", "outputFileSync"
      ] and
      sink = call.getArgument(0)
    ) or
    exists(DataFlow::Node src | isFileCopy(src, sink))
  }
}
module ContextTaint = TaintTracking::Global<ContextTaintConfig>;

predicate isFileCopy(DataFlow::Node src, DataFlow::Node dest) {
  exists(DataFlow::CallNode call, string callee |
    (
      exists(string moduleName |
        moduleName = ["fs", "fs-extra", "node:fs", "node:fs/promises", "fs/promises"] and
        call = DataFlow::moduleMember(moduleName, _).getACall()
      )
      or
      call instanceof DataFlow::MethodCallNode and
      isJoplinFsExtraCall(call.(DataFlow::MethodCallNode))
    ) and
    callee = call.getCalleeName() and
    (callee = "copyFile" or callee = "copyFileSync" or callee = "copy" or callee = "copySync" or callee = "move" or callee = "moveSync" or callee = "rename" or callee = "renameSync") |
    src = call.getArgument(0) and
    dest = call.getArgument(1)
  )
}

predicate isFileWrite(DataFlow::Node path, DataFlow::Node data) {
  exists(DataFlow::CallNode call, string moduleName |
    moduleName = ["fs", "fs-extra", "node:fs", "node:fs/promises", "fs/promises"] and
    call = DataFlow::moduleMember(moduleName, _).getACall() and
    call.getCalleeName() in [
      "writeFile", "writeFileSync", "appendFile", "appendFileSync"
    ] and
    path = call.getArgument(0) and
    data = call.getArgument(1)
  )
}

predicate hasParentDirectorySegment(DataFlow::Node destination) {
  exists(DataFlow::Node partNode, Expr part, string value |
    (
      part = destination.asExpr().getAChildExpr*()
      or
      part = destination.getALocalSource().asExpr().getAChildExpr*()
      or
      partNode = destination.getAPredecessor*() and
      part = partNode.asExpr().getAChildExpr*()
    ) and
    part.mayHaveStringValue(value) and
    (
      value = ".." or
      value.regexpMatch("\\.\\.[/\\\\].*") or
      value.regexpMatch(".*[/\\\\]\\.\\.([/\\\\].*)?")
    )
  )
}

predicate hasUnsafePathTransformation(DataFlow::Node destination) {
  exists(DataFlow::CallNode call |
    call.flowsTo(destination) and
    (
      call = DataFlow::moduleMember(["path", "node:path"], "dirname").getACall()
      or
      call = DataFlow::moduleMember(["path", "node:path"], "resolve").getACall() and
      exists(string value |
        call.getAnArgument().mayHaveStringValue(value) and
        value.regexpMatch("^(/|\\\\\\\\|[a-zA-Z]:[/\\\\]).*")
      )
    )
  )
}

predicate isAuthorizedExportDestination(DataFlow::Node destination) {
  ContextTaint::flow(_, destination) and
  not hasParentDirectorySegment(destination) and
  not hasUnsafePathTransformation(destination)
}

module BackupHijackingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn, string propName |
      isExportModuleCallback(fn, propName) |
      (propName = "onInit" and source = fn.getParameter(0)) or
      (propName = "onClose" and source = fn.getParameter(0)) or
      (propName = "onProcessItem" and (source = fn.getParameter(0) or source = fn.getParameter(1) or source = fn.getParameter(2))) or
      (propName = "onProcessResource" and (source = fn.getParameter(0) or source = fn.getParameter(1) or source = fn.getParameter(2)))
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink) or
    isCommandExecutionSink(sink) or
    isCommandExecutionArgumentSink(sink) or
    exists(DataFlow::Node path |
      isFileWrite(path, sink) and
      not isAuthorizedExportDestination(path)
    ) or
    exists(FileSystemWriteAccess access |
      sink = access.getADataNode() and
      not isAuthorizedExportDestination(access.getAPathArgument())
    ) or
    exists(DataFlow::MethodCallNode call |
      isJoplinFsExtraCall(call) and
      call.getMethodName() in [
        "writeFile", "writeFileSync", "appendFile", "appendFileSync", "outputFile", "outputFileSync"
      ] and
      sink = call.getArgument(1) and
      not isAuthorizedExportDestination(call.getArgument(0))
    ) or
    exists(DataFlow::Node dest |
      isFileCopy(sink, dest) and
      not isAuthorizedExportDestination(dest)
    )
  }
}

module BackupHijacking = TaintTracking::Global<BackupHijackingConfig>;
import BackupHijacking::PathGraph

from BackupHijacking::PathNode source, BackupHijacking::PathNode sink
where BackupHijacking::flowPath(source, sink)
select sink.getNode(), source, sink, "[High Confidence] Backup Hijacking Alert: Export data is confirmed flowing into a network request, terminal command, or unauthorized file path instead of the legitimate export destination."
