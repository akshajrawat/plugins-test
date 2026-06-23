/**
 * @name Native Binary Dropping & Cryptojacking
 * @description Detects dynamic execution of native binaries or cryptominers.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin cryptojacking
 * @id js/joplin/cryptojacking
 */
import javascript
import DataFlow::PathGraph
import JoplinSinks

class CryptojackingConfig extends TaintTracking::Configuration {
  CryptojackingConfig() { this = "CryptojackingConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" | source = call) or
    exists(source.getStringValue())
  }

  override predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isCommandExecutionSink(sink)
  }
}

predicate isElevatedSpawn(DataFlow::Node sink) {
  exists(DataFlow::CallNode call, DataFlow::Node options |
    (sink = call.getArgument(0) or sink = call.getArgument(1)) and
    (
      call = DataFlow::moduleMember("child_process", "spawn").getACall() or
      call = DataFlow::moduleMember("child_process", "spawnSync").getACall() or
      call = DataFlow::moduleMember("node:child_process", "spawn").getACall() or
      call = DataFlow::moduleMember("node:child_process", "spawnSync").getACall() or
      call = DataFlow::moduleMember("child_process", "execFile").getACall() or
      call = DataFlow::moduleMember("child_process", "execFileSync").getACall() or
      call = DataFlow::moduleMember("node:child_process", "execFile").getACall() or
      call = DataFlow::moduleMember("node:child_process", "execFileSync").getACall()
    ) and
    (options = call.getArgument(1) or options = call.getArgument(2)) and
    exists(Property prop | 
      prop = options.getALocalSource().asExpr().(ObjectExpr).getAProperty() and
      prop.getName() = "shell"
    )
  )
}

from DataFlow::PathNode source, DataFlow::PathNode sink, CryptojackingConfig cfg, string msg
where cfg.hasFlowPath(source, sink) and
  (
    source.getNode().getStringValue().regexpMatch("(?i).*(xmrig|minerd|ethminer|cgminer|t-rex|nsfminer|pool\\.|stratum\\+tcp).*") or
    not exists(source.getNode().getStringValue())
  ) and
  (
    if isElevatedSpawn(sink.getNode())
    then msg = "[ELEVATED SEVERITY] Cryptojacking/Native binary execution detected (spawn with shell: true)."
    else msg = "Cryptojacking or native binary execution detected."
  )
select sink.getNode(), source, sink, msg
