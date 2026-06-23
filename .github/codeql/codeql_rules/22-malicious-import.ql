/**
 * @name Malicious Import Module
 * @description Detects if data read from an imported file inside registerImportModule flows to a dangerous sink (network or command execution).
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin malicious-import
 * @id joplin/malicious-import
 */
import javascript
import DataFlow::PathGraph
import JoplinSinks

predicate isImportModuleRegistration(DataFlow::MethodCallNode reg) {
  reg.getMethodName() = "registerImportModule" and
  (
    exists(DataFlow::PropRead pr |
      pr.getPropertyName() = "interop" and
      reg.getReceiver().getALocalSource() = pr
    ) or
    reg.getReceiver().(DataFlow::PropRead).getPropertyName() = "interop"
  )
}

predicate isImportModuleCallback(DataFlow::FunctionNode fn) {
  exists(DataFlow::MethodCallNode reg |
    isImportModuleRegistration(reg) and
    exists(ObjectExpr obj |
      obj = reg.getArgument(0).getALocalSource().asExpr() and
      exists(Property prop |
        prop = obj.getAProperty() and
        prop.getName() = "onExec" and
        fn.asExpr() = prop.getInit()
      )
    )
  )
}

class MaliciousImportConfig extends TaintTracking::Configuration {
  MaliciousImportConfig() { this = "MaliciousImportConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn |
      isImportModuleCallback(fn) and
      // The first parameter of onExec contains the context/data being imported
      source = fn.getParameter(0)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isNetworkExfiltrationSink(sink) or
    JoplinSinks::isCommandExecutionSink(sink)
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, MaliciousImportConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Malicious Import: Data from imported file flows to a dangerous sink (network or OS command). Requires human review."
