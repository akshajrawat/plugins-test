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
    source.asExpr() instanceof StringLiteral or
    source.asExpr() instanceof TemplateLiteral or
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" | source = call)
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleMember("child_process", "exec").getACall() or
      call = DataFlow::moduleMember("child_process", "execFile").getACall() or
      call = DataFlow::moduleMember("child_process", "spawn").getACall()
    |
      sink = call.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, CryptojackingConfig cfg
where cfg.hasFlowPath(source, sink) and
  (
    source.getNode().getStringValue().regexpMatch("(?i).*(xmrig|minerd|ethminer|cgminer|t-rex|nsfminer|pool\\.|stratum\\+tcp).*") or
    not (source.getNode().asExpr() instanceof StringLiteral or source.getNode().asExpr() instanceof TemplateLiteral)
  )
select sink.getNode(), source, sink, "Cryptojacking or native binary execution detected."
