/**
 * @name Native Binary Dropping & Cryptojacking
 * @description Detects dynamic execution of native binaries or cryptominers.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin cryptojacking
 * @id js/joplin/cryptojacking
 */
import javascript

import JoplinSinks

module CryptojackingConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call | call = DataFlow::globalVarRef("fetch").getACall() | source = call) or
    exists(source.getStringValue())
  }

  predicate isSink(DataFlow::Node sink) {
    isCommandExecutionSink(sink)
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
      prop.getName() = "shell" and
      prop.getInit().(BooleanLiteral).getValue() = "true"
    )
  )
}

module CryptojackFlow = TaintTracking::Global<CryptojackingConfig>;
import CryptojackFlow::PathGraph

from CryptojackFlow::PathNode source, CryptojackFlow::PathNode sink, string msg
where CryptojackFlow::flowPath(source, sink) and
  (
    source.getNode().getStringValue().regexpMatch("(?i).*(xmrig|minerd|ethminer|cgminer|t-rex|nsfminer|pool\\.|stratum\\+tcp).*") or
    not exists(source.getNode().getStringValue())
  ) and
  (
    if isElevatedSpawn(sink.getNode())
    then msg = "[ELEVATED SEVERITY] High-Risk Execution: The plugin is passing external payloads or cryptominer keywords to a system terminal command with `shell: true`. \\n**Reviewer Action:** This is a critical threat indicator. The use of `shell: true` means this input is interpreted by a shell environment and is significantly easier to weaponize. Immediately audit the command payload for malware or resource hijacking."
    else msg = "High-Risk Execution: The plugin is downloading external payloads or contains hardcoded keywords associated with cryptominers, and passing them directly to a system terminal command. \\n**Reviewer Action:** This is a severe threat indicator. Immediately audit the command payload to ensure it is not silently installing malware or hijacking CPU resources."
  )
select sink.getNode(), source, sink, msg
