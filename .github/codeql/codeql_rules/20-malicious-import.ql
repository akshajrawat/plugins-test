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
import JoplinSources

predicate isImportModuleRegistration(DataFlow::MethodCallNode reg) {
  reg.getMethodName() = "registerImportModule" and
  reg.getReceiver().getALocalSource() = Joplin::interop()
}

predicate isImportModuleCallback(DataFlow::FunctionNode fn) {
  exists(DataFlow::MethodCallNode reg |
    isImportModuleRegistration(reg) and
    fn = reg.getArgument(0).getALocalSource().getAPropertyWrite("onExec").getRhs().getALocalSource()
  )
}

module MaliciousImportConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode fn |
      isImportModuleCallback(fn) and
      (
        source = fn.getParameter(0) or
        source = fn.getParameter(0).getAPropertyRead("sourcePath")
      )
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode readCall |
      readCall.getCalleeName() in ["readFile", "readFileSync", "readJSON", "readJSONSync", "readFileString"] and
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
    isCommandExecutionSink(sink) or
    isFileSystemPathSink(sink) or
    isFileSystemDataSink(sink)
  }
}

module MaliciousImportFlow = TaintTracking::Global<MaliciousImportConfig>;
import MaliciousImportFlow::PathGraph

from MaliciousImportFlow::PathNode source, MaliciousImportFlow::PathNode sink
where MaliciousImportFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Malicious Import Processing: Data read during a custom `registerImportModule` execution is flowing into a dangerous sink (network exfiltration, OS command execution, or unauthorized file writes)."
