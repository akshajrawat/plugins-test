/**
 * @name Command Execution
 * @description Detects execution of terminal commands via child_process.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin command-execution
 * @id js/joplin/command-execution
 */
import javascript
import DataFlow::PathGraph
import JoplinSources

class CommandExecutionConfig extends TaintTracking::Configuration {
  CommandExecutionConfig() { this = "CommandExecutionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source = Joplin::settingsGlobalValue() or
    source = Joplin::data().getAMethodCall("get") or
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" | source = call) or
    source = Joplin::workspace().getAMethodCall("onNoteChange").getArgument(0).(DataFlow::FunctionNode).getParameter(0) or
    source = Joplin::workspace().getAMethodCall("onNoteContentChange").getArgument(0).(DataFlow::FunctionNode).getParameter(0) or
    source instanceof DataFlow::ParameterNode or
    exists(source.getStringValue())
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call, string moduleName, string methodName |
      (moduleName = "child_process" or moduleName = "node:child_process") and
      (
        methodName = "exec" or methodName = "execFile" or methodName = "spawn" or
        methodName = "execSync" or methodName = "execFileSync" or methodName = "spawnSync" or
        methodName = "fork"
      ) and
      call = DataFlow::moduleMember(moduleName, methodName).getACall()
    |
      sink = call.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, CommandExecutionConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Execution of a terminal command via child_process. Requires human review."
