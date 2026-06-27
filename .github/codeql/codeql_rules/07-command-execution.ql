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
    source = Joplin::workspace().getAMethodCall("selectedNote") or
    source instanceof DataFlow::ParameterNode or
    (
      exists(source.getStringValue()) and
      not source.getStringValue().regexpMatch("(?i).*(xmrig|minerd|ethminer|cgminer|t-rex|nsfminer|pool\\.|stratum\\+tcp).*")
    )
  }

  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isCommandExecutionSink(sink)
  }
}

module CommandExecFlow = TaintTracking::Global<CommandExecutionConfig>;
import CommandExecFlow::PathGraph

from CommandExecFlow::PathNode source, CommandExecFlow::PathNode sink
where CommandExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Terminal Command Execution: The plugin is passing generic string data or Joplin settings into a system terminal command (`child_process`). \\n**Reviewer Action:** Note: this is the broadest, lowest-specificity command-execution check — cross-reference with Rule 2 (Secret Theft) and Rule 6 (Cryptojacking) if this same call also appears there. Review the executed command to ensure the inputs are properly sanitized against command injection."
