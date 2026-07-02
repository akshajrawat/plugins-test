/**
 * @name Asynchronous Tag Flooding & Search Poisoning
 * @description Sabotaging application indexing via programmatic high-volume metadata inflation.
 * @kind problem
 * @problem.severity warning
 * @id joplin/tag-flooding
 */
import javascript
import JoplinSources

// ==========================================
// Loop detection
// ==========================================

predicate isUnboundedInterval(DataFlow::CallNode timer) {
  timer = DataFlow::globalVarRef("setInterval").getACall() and
  not exists(DataFlow::CallNode clear |
    clear = DataFlow::globalVarRef("clearInterval").getACall() and
    clear.getArgument(0).getALocalSource() = timer.getALocalSource()
  )
}

predicate isAlwaysTrueCondition(Expr condition) {
  condition.stripParens() instanceof BooleanLiteral and
  condition.stripParens().(BooleanLiteral).getBoolValue() = true
  or
  condition.stripParens() instanceof NumberLiteral and
  condition.stripParens().(NumberLiteral).getValue() = "1"
}

predicate isRecursiveSetTimeout(DataFlow::CallNode call) {
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
  )
}

predicate inUnboundedLoop(DataFlow::CallNode call) {
  // Inside a synchronous loop with no normal finite bound.
  exists(LoopStmt loop |
    (
      (loop instanceof WhileStmt and isAlwaysTrueCondition(loop.getTest())) or
      (loop instanceof DoWhileStmt and isAlwaysTrueCondition(loop.getTest())) or
      (loop instanceof ForStmt and not exists(loop.getTest())) or
      (loop instanceof ForStmt and isAlwaysTrueCondition(loop.getTest()))
    ) and
    call.asExpr().getEnclosingStmt().getParentStmt*() = loop
  )
  or
  // Inside an uncleared setInterval loop
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    isUnboundedInterval(timer) and
    callback = timer.getArgument(0).getAFunctionValue() and
    call.getContainer().getEnclosingContainer*() = callback.getFunction()
  )
  or
  // Recursive setTimeout
  isRecursiveSetTimeout(call)
}

predicate inAnyLoop(DataFlow::CallNode call) {
  inUnboundedLoop(call) or
  exists(LoopStmt loop | call.asExpr().getEnclosingStmt().getParentStmt*() = loop) or
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    timer = DataFlow::globalVarRef("setInterval").getACall() and
    callback = timer.getArgument(0).getAFunctionValue() and
    call.getContainer().getEnclosingContainer*() = callback.getFunction()
  ) or
  exists(DataFlow::MethodCallNode arrayCall |
    arrayCall.getMethodName() in ["forEach", "map"] and
    call.getContainer().getEnclosingContainer*() = arrayCall.getArgument(0).getAFunctionValue().getFunction()
  )
}

// ==========================================
// Target Paths & Write Calls
// ==========================================

predicate isTargetPath(DataFlow::Node pathArg) {
  exists(DataFlow::ArrayCreationNode arr, string root | 
    arr = pathArg.getALocalSource() and
    root = arr.getElement(0).getStringValue() and
    (
      root in ["tags", "notes", "resources"] or
      // ["tags", id, "notes"]
      (root = "tags" and arr.getElement(2).getStringValue() = "notes")
    )
  )
}

predicate isFileWrite(DataFlow::CallNode call) {
  exists(string meth | meth in ["writeFile", "writeFileSync", "appendFile", "appendFileSync"] |
    call = DataFlow::moduleMember("fs", meth).getACall() or
    call = DataFlow::moduleMember("fs-extra", meth).getACall() or
    // joplin.require('fs-extra')
    exists(DataFlow::CallNode req |
      req = Joplin::joplin().getAMethodCall("require") and
      req.getArgument(0).getStringValue() in ["fs", "fs-extra"] and
      call = req.getAMethodCall(meth)
    )
  )
}

predicate isLargeWritePayload(DataFlow::Node payload) {
  // Check if string literal is suspiciously large or if Buffer.alloc is used heavily
  payload.getStringValue().length() > 10000 or
  exists(DataFlow::CallNode alloc |
    alloc = DataFlow::globalVarRef("Buffer").getAMethodCall("alloc") and
    alloc.getArgument(0).getIntValue() > 10000 and
    payload = alloc
  )
}

// ==========================================
// Query
// ==========================================

from DataFlow::CallNode call, string msg
where
  (
    // 1. Data POST to flooding target inside an unbounded/background loop
    call = Joplin::data().getAMethodCall("post") and
    isTargetPath(call.getArgument(0)) and
    inUnboundedLoop(call) and
    msg = "Resource Exhaustion: The plugin is creating tags, notes, or resources from an unbounded or background loop. Ensure loops have finite execution limits."
  )
  or
  (
    // 2. ANY file write inside an UNBOUNDED loop
    isFileWrite(call) and
    inUnboundedLoop(call) and
    msg = "Disk Quota Exhaustion: The plugin is writing to the filesystem inside an unbounded or infinite loop. This will rapidly exhaust disk space. Ensure loops have finite execution limits."
  )
  or
  (
    // 3. LARGE file write inside ANY loop
    isFileWrite(call) and
    isLargeWritePayload(call.getArgument(1).getALocalSource()) and
    inAnyLoop(call) and
    msg = "Disk Quota Exhaustion: The plugin is writing large chunks of data to the filesystem inside a loop. Verify this is intended user-initiated behavior and won't overwhelm local storage."
  )
select call, msg
