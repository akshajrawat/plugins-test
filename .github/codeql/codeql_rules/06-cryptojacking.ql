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

class CryptojackingConfig extends TaintTracking::Configuration {
  CryptojackingConfig() { this = "CryptojackingConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" | source = call) or
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

predicate isElevatedSpawn(DataFlow::Node sink) {
  exists(DataFlow::CallNode call |
    sink = call.getArgument(0) and
    (call = DataFlow::moduleMember("child_process", "spawn").getACall() or
     call = DataFlow::moduleMember("child_process", "spawnSync").getACall() or
     call = DataFlow::moduleMember("node:child_process", "spawn").getACall() or
     call = DataFlow::moduleMember("node:child_process", "spawnSync").getACall()) and
    exists(Property prop | 
      prop = call.getArgument(2).getALocalSource().asExpr().(ObjectExpr).getAProperty() and
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
