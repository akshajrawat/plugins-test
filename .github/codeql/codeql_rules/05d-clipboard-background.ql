/**
 * @name Clipboard Hijacking (Background)
 * @description Detects clipboard reads or writes inside repeated loops, iteration callbacks, or recurring timers.
 * @kind problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-background
 */
import javascript
import JoplinSources

predicate functionDirectlyCalls(DataFlow::FunctionNode caller, DataFlow::FunctionNode callee) {
  exists(DataFlow::CallNode invocation |
    invocation.getContainer() = caller.getFunction() and
    callee = invocation.getCalleeNode().getAFunctionValue()
  )
}

predicate callbackExecutesCall(DataFlow::FunctionNode callback, DataFlow::CallNode call) {
  exists(DataFlow::FunctionNode owner |
    call.getContainer() = owner.getFunction() and
    functionDirectlyCalls*(callback, owner)
  )
}

predicate isInsideLoop(DataFlow::CallNode call) {
  exists(LoopStmt loop |
    call.asExpr().getEnclosingStmt().getParentStmt*() = loop and
    call.asExpr().getContainer() = loop.getContainer()
  )
}

predicate isInsideInterval(DataFlow::CallNode call) {
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    timer = DataFlow::globalVarRef("setInterval").getACall() and
    callback = timer.getArgument(0).getAFunctionValue() and
    callbackExecutesCall(callback, call)
  )
}

predicate isInsideRecursiveTimeout(DataFlow::CallNode call) {
  exists(
    DataFlow::FunctionNode recurringCallback,
    DataFlow::CallNode timer,
    DataFlow::FunctionNode scheduledCallback
  |
    callbackExecutesCall(recurringCallback, call) and
    timer = DataFlow::globalVarRef("setTimeout").getACall() and
    callbackExecutesCall(recurringCallback, timer) and
    scheduledCallback = timer.getArgument(0).getAFunctionValue() and
    functionDirectlyCalls*(scheduledCallback, recurringCallback)
  )
}

predicate isInsideIterationCallback(DataFlow::CallNode call) {
  exists(DataFlow::MethodCallNode iterationCall, DataFlow::FunctionNode callback |
    iterationCall.getMethodName() in ["forEach", "map"] and
    callback = iterationCall.getArgument(0).getAFunctionValue() and
    callbackExecutesCall(callback, call)
  )
}

predicate isRepeatedClipboardAccess(DataFlow::CallNode call) {
  isInsideLoop(call) or
  isInsideInterval(call) or
  isInsideRecursiveTimeout(call) or
  isInsideIterationCallback(call)
}

from DataFlow::MethodCallNode call
where
  call.getReceiver().getALocalSource() = Joplin::clipboard() and
  call.getMethodName() in [
    "readText", "readHtml", "readImage", "writeText", "writeHtml", "writeImage", "write"
  ] and
  isRepeatedClipboardAccess(call)
select call, "Repeated Clipboard Access: The plugin is reading or writing the clipboard inside a loop, iteration callback, or recurring timer. Verify that this repeated access is explicitly initiated and expected by the user."
