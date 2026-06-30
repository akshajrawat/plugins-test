/**
 * @name Malicious Import Module
 * @description Detects if data read from an imported file inside registerImportModule flows to a dangerous sink (network or command execution).
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin malicious-import
 * @id joplin/malicious-import
 */
import javascript
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

module MaliciousImportConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn |
      isImportModuleCallback(fn) and
      // The first parameter of onExec contains the context/data being imported
      source = fn.getParameter(0)
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode readCall |
      readCall.getCalleeName() in ["readFile", "readFileSync", "readJSON", "readJSONSync", "readFileString", "read"] and
      node1 = readCall.getArgument(0) and
      (
        node2 = readCall
        or
        exists(int i, DataFlow::FunctionNode cb | (i = 1 or i = 2) and cb = readCall.getArgument(i).getAFunctionValue() and node2 = cb.getParameter(1))
      )
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink) or
    isCommandExecutionSink(sink)
  }
}

module MaliciousImportFlow = TaintTracking::Global<MaliciousImportConfig>;
import MaliciousImportFlow::PathGraph

from MaliciousImportFlow::PathNode source, MaliciousImportFlow::PathNode sink
where MaliciousImportFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Malicious Import Processing: Data read during a custom `registerImportModule` execution is flowing into a dangerous sink (network exfiltration or OS command execution). \\n**Reviewer Action:** Importing a note should only result in note creation. Verify why the plugin needs to execute commands or phone home based on the contents of an imported file. Ensure strict sanitization."
