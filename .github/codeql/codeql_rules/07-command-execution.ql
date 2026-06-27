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
select sink.getNode(), source, sink, "Execution of a terminal command via child_process (broad/residual pattern — see Secret Key Theft and Cryptojacking rules for higher-confidence variants of overlapping sources). Requires human review."
