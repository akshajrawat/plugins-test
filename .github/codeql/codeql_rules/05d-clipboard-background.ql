/**
 * @name Clipboard Hijacking (Background)
 * @description Detects silent clipboard reads or writes happening inside an unbounded loop or interval.
 * @kind problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-background
 */
import javascript
import JoplinSources

/** Checks if a call is inside any loop construct. */
predicate inAnyLoop(DataFlow::CallNode call) {
  exists(LoopStmt loop | call.asExpr().getEnclosingStmt().getParentStmt*() = loop) or
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    timer = DataFlow::globalVarRef("setInterval").getACall() and
    callback = timer.getArgument(0).getAFunctionValue() and
    call.getContainer().getEnclosingContainer*() = callback.getFunction()
  ) or
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    timer = DataFlow::globalVarRef("setTimeout").getACall() and
    callback = timer.getArgument(0).getAFunctionValue() and
    (
      exists(DataFlow::CallNode innerTimer |
        innerTimer = DataFlow::globalVarRef("setTimeout").getACall() and
        innerTimer.getContainer().getEnclosingContainer*() = callback.getFunction() and
        innerTimer.getArgument(0).getAFunctionValue() = callback
      )
    ) and
    call.getContainer().getEnclosingContainer*() = callback.getFunction()
  ) or
  exists(DataFlow::MethodCallNode arrayCall |
    arrayCall.getMethodName() in ["forEach", "map"] and
    call.getContainer().getEnclosingContainer*() = arrayCall.getArgument(0).getAFunctionValue().getFunction()
  )
}

from DataFlow::MethodCallNode call
where
  call.getReceiver().getALocalSource() = Joplin::clipboard() and
  (call.getMethodName() = "readText" or call.getMethodName() = "writeText" or call.getMethodName() = "writeHtml") and
  inAnyLoop(call)
select call, "Silent Clipboard Access: The plugin is reading or writing the clipboard inside a loop or background interval. \\n**Reviewer Action:** This is a severe threat indicator for silent clipboard hijacking or monitoring. Verify that the user has explicitly authorized this continuous access."
