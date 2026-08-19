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
import JoplinLinks

module DynamicCodeExecutionConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    Joplin::isRemoteDataSource(source) or

    // Direct http/https
    exists(DataFlow::CallNode call |
      call = DataFlow::moduleMember("http", "get").getACall() or
      call = DataFlow::moduleMember("https", "get").getACall() or
      call = DataFlow::moduleMember("http", "request").getACall() or
      call = DataFlow::moduleMember("https", "request").getACall() or
      call = DataFlow::moduleMember("node:http", "get").getACall() or
      call = DataFlow::moduleMember("node:https", "get").getACall() or
      call = DataFlow::moduleMember("node:http", "request").getACall() or
      call = DataFlow::moduleMember("node:https", "request").getACall()
    | source = call) or
    
    // userDataGet smuggled payloads
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "userDataGet" and
      call.getReceiver().getALocalSource() = Joplin::data()
    | source = call) or

    // superagent
    exists(DataFlow::Node saReq |
      saReq = DataFlow::moduleImport("superagent").getAMethodCall()
    |
      source = saReq or
      exists(DataFlow::MethodCallNode thenCall, DataFlow::FunctionNode cb |
        thenCall.getMethodName() = "then" and
        thenCall.getReceiver().getALocalSource*() = saReq and
        cb = thenCall.getArgument(0).getAFunctionValue() and
        source = cb.getParameter(0)
      ) or
      exists(DataFlow::MethodCallNode endCall, DataFlow::FunctionNode cb |
        endCall.getMethodName() = "end" and
        endCall.getReceiver().getALocalSource*() = saReq and
        cb = endCall.getArgument(0).getAFunctionValue() and
        source = cb.getParameter(1)
      )
    )
    or
    // restricted event sources
    exists(DataFlow::MethodCallNode onCall, DataFlow::Node receiver, DataFlow::FunctionNode cb |
      (onCall.getMethodName() = "on" or onCall.getMethodName() = "addEventListener") and
      (onCall.getArgument(0).getStringValue() = "message" or onCall.getArgument(0).getStringValue() = "data") and
      receiver = onCall.getReceiver().getALocalSource() and
      (
        receiver = DataFlow::globalVarRef("window") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("http", "request") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("https", "request") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("http", "get") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("https", "get") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("node:http", "request") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("node:https", "request") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("node:http", "get") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("node:https", "get") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("ws", "WebSocket") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("worker_threads", "Worker") or
        receiver.(DataFlow::InvokeNode).getCalleeNode().getALocalSource() = DataFlow::moduleMember("worker_threads", "MessagePort") or
        (
          receiver.(DataFlow::PropRead).getPropertyName() in ["port1", "port2"] and
          receiver.(DataFlow::PropRead).getBase().(DataFlow::InvokeNode).getCalleeNode().getALocalSource() =
            DataFlow::moduleMember("worker_threads", "MessageChannel")
        )
      ) and
      cb = onCall.getArgument(1).getAFunctionValue() and
      source = cb.getParameter(0)
    ) or
    Joplin::isJoplinMessageSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    sink = DataFlow::globalVarRef("eval").getAnInvocation().getAnArgument() or
    
    // Function sink - last argument is the body
    exists(DataFlow::InvokeNode fnCall |
      fnCall = DataFlow::globalVarRef("Function").getAnInstantiation() or
      fnCall = DataFlow::globalVarRef("Function").getACall() or
      fnCall.getCalleeName() = "Function"
    |
      sink = fnCall.getLastArgument()
    ) or
    
    sink = DataFlow::globalVarRef("setTimeout").getAnInvocation().getArgument(0) or
    sink = DataFlow::globalVarRef("setInterval").getAnInvocation().getArgument(0) or
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

class AxiosDataTaintStep extends TaintTracking::SharedTaintStep {
  override predicate step(DataFlow::Node pred, DataFlow::Node succ) {
    exists(DataFlow::PropRead read |
      read.getPropertyName() = "data" and
      read.getBase() = pred and
      succ = read
    )
  }
}

module DynCodeExecFlow = TaintTracking::Global<DynamicCodeExecutionConfig>;
import DynCodeExecFlow::PathGraph

from DynCodeExecFlow::PathNode source, DynCodeExecFlow::PathNode sink
where DynCodeExecFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Remote data flows to dynamic code execution. Verify if the endpoint is a trusted Joplin service or a remote server."
