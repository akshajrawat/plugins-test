/**
 * @name Dynamic Code Execution
 * @description Detects dynamic code execution from remote sources.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin dynamic-code-execution
 * @id js/joplin/dynamic-code-execution
 */
import javascript

import JoplinSources

module DynamicCodeExecutionConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "fetch" or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleImport("node-fetch") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleImport("got") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleImport("superagent") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", "get") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("http", "get") or
      call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("https", "get")
    |
      source = call
    )
    or
    exists(DataFlow::MethodCallNode onCall |
      (onCall.getMethodName() = "on" or onCall.getMethodName() = "addEventListener") and
      (onCall.getArgument(0).getStringValue() = "message" or onCall.getArgument(0).getStringValue() = "data")
    |
      source = onCall.getArgument(1).getALocalSource().(DataFlow::FunctionNode).getParameter(0)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    sink = DataFlow::globalVarRef("eval").getACall().getAnArgument() or
    sink = DataFlow::globalVarRef("Function").getAnInstantiation().getAnArgument() or
    sink = DataFlow::globalVarRef("setTimeout").getACall().getArgument(0) or
    sink = DataFlow::globalVarRef("setInterval").getACall().getArgument(0) or
    exists(DataFlow::InvokeNode vmInvoke |
      vmInvoke.getCalleeNode().getALocalSource() = DataFlow::moduleMember("vm", "runInNewContext") or
      vmInvoke.getCalleeNode().getALocalSource() = DataFlow::moduleMember("vm", "runInThisContext") or
      vmInvoke.getCalleeNode().getALocalSource() = DataFlow::moduleMember("vm", "runInContext") or
      vmInvoke.getCalleeNode().getALocalSource() = DataFlow::moduleMember("vm", "compileFunction") or
      vmInvoke.getCalleeNode().getALocalSource() = DataFlow::moduleMember("vm", "Script")
    |
      sink = vmInvoke.getArgument(0)
    )
  }

}

module DynCodeExecFlow = TaintTracking::Global<DynamicCodeExecutionConfig>;
import DynCodeExecFlow::PathGraph

from DynCodeExecFlow::PathNode source, DynCodeExecFlow::PathNode sink
where DynCodeExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote data flows to dynamic code execution. \\n**Reviewer Action:** Verify if the endpoint is a trusted Joplin service or a remote server. If code execution is intended, check for strict code signing, content-hash validation, or sandboxing to ensure an attacker cannot inject arbitrary payloads via the network."
