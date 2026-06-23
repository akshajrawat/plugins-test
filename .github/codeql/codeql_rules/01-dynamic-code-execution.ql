/**
 * @name Dynamic Code Execution
 * @description Detects dynamic code execution from remote sources.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin dynamic-code-execution
 * @id js/joplin/dynamic-code-execution
 */
import javascript
import DataFlow::PathGraph
import JoplinSources

class DynamicCodeExecutionConfig extends TaintTracking::Configuration {
  DynamicCodeExecutionConfig() { this = "DynamicCodeExecutionConfig" }

  override predicate isSource(DataFlow::Node source) {
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

  override predicate isSink(DataFlow::Node sink) {
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

from DataFlow::PathNode source, DataFlow::PathNode sink, DynamicCodeExecutionConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Remote data flows to dynamic code execution."
