/**
 * @name Clipboard Execution
 * @description Detects reading the user's clipboard and executing it as code or passing it to the terminal.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-execution
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isCodeExecutionSink(DataFlow::Node sink) {
  isCommandExecutionSink(sink) or
  sink = DataFlow::globalVarRef("eval").getAnInvocation().getArgument(0) or
  sink = DataFlow::globalVarRef("setTimeout").getAnInvocation().getArgument(0) or
  sink = DataFlow::globalVarRef("setInterval").getAnInvocation().getArgument(0) or
  exists(DataFlow::InvokeNode functionCall |
    functionCall = DataFlow::globalVarRef("Function").getAnInstantiation() or
    functionCall = DataFlow::globalVarRef("Function").getACall()
  |
    sink = functionCall.getLastArgument()
  ) or
  exists(DataFlow::InvokeNode vmCall, string moduleName |
    moduleName in ["vm", "node:vm"] and
    (
      vmCall.getCalleeNode().getALocalSource() = DataFlow::moduleMember(moduleName, "runInThisContext") or
      vmCall.getCalleeNode().getALocalSource() = DataFlow::moduleMember(moduleName, "runInNewContext") or
      vmCall.getCalleeNode().getALocalSource() = DataFlow::moduleMember(moduleName, "runInContext") or
      vmCall.getCalleeNode().getALocalSource() = DataFlow::moduleMember(moduleName, "compileFunction") or
      vmCall.getCalleeNode().getALocalSource() = DataFlow::moduleMember(moduleName, "Script")
    ) and
    sink = vmCall.getArgument(0)
  )
}

module ClipboardExecutionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::MethodCallNode call |
      call.getReceiver().getALocalSource() = Joplin::clipboard() and
      call.getMethodName() in ["readText", "readHtml"] and
      source = call
    )
  }
  predicate isSink(DataFlow::Node sink) {
    isCodeExecutionSink(sink)
  }
}

module ClipboardExecutionFlow = TaintTracking::Global<ClipboardExecutionConfig>;
import ClipboardExecutionFlow::PathGraph

from ClipboardExecutionFlow::PathNode source, ClipboardExecutionFlow::PathNode sink
where ClipboardExecutionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard Execution Risk: The plugin is reading the user's clipboard and passing its contents into a code evaluation or terminal command sink."
