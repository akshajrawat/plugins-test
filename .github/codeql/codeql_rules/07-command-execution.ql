/**
 * @name Command Execution
 * @description Detects execution of terminal commands via child_process.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin command-execution
 * @id js/joplin/command-execution
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isJoplinEventCallbackParameter(DataFlow::Node source) {
  exists(DataFlow::MethodCallNode onCall, DataFlow::FunctionNode callback |
    onCall.getMethodName().regexpMatch("(?i)^on.*") and
    (
      onCall.getReceiver().getALocalSource() = Joplin::workspace() or
      onCall.getReceiver().getALocalSource() = Joplin::panels() or
      onCall.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("dialogs") or
      onCall.getReceiver().getALocalSource() = Joplin::joplin().getAPropertyRead("views").getAPropertyRead("editors")
    ) and
    callback = onCall.getArgument(0).getALocalSource() and
    source = callback.getParameter(_)
  ) or
  Joplin::isJoplinMessageSource(source)
}

module CommandExecutionConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call, Expr argExpr, string settingName |
      call = Joplin::settingsGlobalValue() and
      argExpr = call.getArgument(0).asExpr() and
      (settingName = argExpr.getStringValue() or settingName = argExpr.(ArrayExpr).getAnElement().getStringValue()) and
      not Joplin::isSensitiveSetting(settingName)
    | source = call
    ) or
    source = Joplin::data().getAMethodCall("get") or
    source = Joplin::data().getAMethodCall("userDataGet") or
    source = Joplin::workspace().getAMethodCall("selectedNote") or
    isJoplinEventCallbackParameter(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isCommandExecutionSink(sink) or
    isCommandExecutionArgumentSink(sink)
  }
}

module CommandExecFlow = TaintTracking::Global<CommandExecutionConfig>;
import CommandExecFlow::PathGraph

from CommandExecFlow::PathNode source, CommandExecFlow::PathNode sink
where CommandExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Terminal Command Execution: This code executes an external terminal command."
