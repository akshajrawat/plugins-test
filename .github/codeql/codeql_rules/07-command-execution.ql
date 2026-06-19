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
    source instanceof DataFlow::ParameterNode or
    source.asExpr() instanceof StringLiteral or
    source.asExpr() instanceof TemplateLiteral
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleMember("child_process", "exec").getACall() or
      call = DataFlow::moduleMember("child_process", "execSync").getACall() or
      call = DataFlow::moduleMember("child_process", "spawn").getACall() or
      call = DataFlow::moduleMember("child_process", "execFile").getACall()
    |
      sink = call.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, CommandExecutionConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Execution of a terminal command via child_process. Requires human review."
