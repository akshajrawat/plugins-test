/**
 * @name Silent Backup Hijacking (Structural)
 * @description Detects network, command, or filesystem operations executed from Joplin export callbacks without requiring proven taint flow.
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

predicate functionDirectlyExecutes(
  DataFlow::FunctionNode caller, DataFlow::FunctionNode callee
) {
  exists(DataFlow::CallNode invocation |
    invocation.getContainer() = caller.getFunction() and
    (
      callee = invocation.getCalleeNode().getAFunctionValue() or
      callee = invocation.getAnArgument().getAFunctionValue()
    )
  )
}

predicate callbackExecutesCall(DataFlow::FunctionNode callback, DataFlow::CallNode call) {
  exists(DataFlow::FunctionNode owner |
    call.getContainer() = owner.getFunction() and
    functionDirectlyExecutes*(callback, owner)
  )
}

predicate isTwoPathFileOperation(DataFlow::CallNode call) {
  call.getCalleeName() in [
    "copyFile", "copyFileSync", "copy", "copySync",
    "move", "moveSync", "rename", "renameSync"
  ] and
  isFileSystemPathSink(call.getArgument(1))
}

/** Gets the path that a filesystem operation writes, creates, moves, or extracts to. */
predicate getFileSystemTarget(DataFlow::CallNode call, DataFlow::Node target) {
  isTwoPathFileOperation(call) and
  target = call.getArgument(1)
  or
  isArchiveExtractionDestinationSink(call.getArgument(1)) and
  target = call.getArgument(1)
  or
  not isTwoPathFileOperation(call) and
  not isArchiveExtractionDestinationSink(call.getArgument(1)) and
  isFileSystemPathSink(call.getArgument(0)) and
  target = call.getArgument(0)
}

module ExportDestinationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn |
      isExportModuleCallback(fn, _) and
      source = fn.getParameter(0).getAPropertyRead("destPath")
    )
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call | getFileSystemTarget(call, sink))
  }
}
module ExportDestination = TaintTracking::Global<ExportDestinationConfig>;

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
  ExportDestination::flow(_, destination) and
  not hasParentDirectorySegment(destination) and
  not hasUnsafePathTransformation(destination)
}

from DataFlow::FunctionNode callback, DataFlow::CallNode dangerousCall
where
  isExportModuleCallback(callback, _) and
  callbackExecutesCall(callback, dangerousCall) and
  (
    isNetworkExfiltrationCall(dangerousCall) or
    isCommandExecutionSink(dangerousCall) or
    isCommandExecutionArgumentSink(dangerousCall.getAnArgument()) or
    exists(DataFlow::Node target |
      getFileSystemTarget(dangerousCall, target) and
      not isAuthorizedExportDestination(target)
    )
  )
select dangerousCall, "[Structural Review] Backup Hijacking Indicator: A network request, terminal command, or filesystem operation executes from a Joplin export callback. This structural result does not by itself prove that export data leaves the approved destination. \\n**Reviewer Action:** Verify that the operation is required by the export format and that filesystem targets remain under `context.destPath`."
