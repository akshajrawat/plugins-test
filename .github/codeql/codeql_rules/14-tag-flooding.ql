/**
 * @name Asynchronous Tag Flooding & Search Poisoning
 * @description Sabotaging application indexing via programmatic high-volume metadata inflation.
 * @kind problem
 * @problem.severity warning
 * @id joplin/tag-flooding
 */
import javascript
import JoplinSources
import JoplinSinks

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

predicate directlyInsideUnboundedLoop(DataFlow::CallNode call) {
  exists(LoopStmt loop |
    (
      (loop instanceof WhileStmt and isAlwaysTrueCondition(loop.getTest())) or
      (loop instanceof DoWhileStmt and isAlwaysTrueCondition(loop.getTest())) or
      (loop instanceof ForStmt and not exists(loop.getTest())) or
      (loop instanceof ForStmt and isAlwaysTrueCondition(loop.getTest()))
    ) and
    call.asExpr().getEnclosingStmt().getParentStmt*() = loop and
    call.asExpr().getContainer() = loop.getContainer()
  )
}

predicate directlyInsideAnyLoop(DataFlow::CallNode call) {
  exists(LoopStmt loop |
    call.asExpr().getEnclosingStmt().getParentStmt*() = loop and
    call.asExpr().getContainer() = loop.getContainer()
  )
}

predicate insideRecursiveSetTimeout(DataFlow::CallNode call) {
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

predicate inUnboundedLoop(DataFlow::CallNode call) {
  // Directly inside an infinite synchronous loop.
  directlyInsideUnboundedLoop(call)
  or
  // Reached through a helper called by an infinite synchronous loop.
  exists(DataFlow::CallNode invocation, DataFlow::FunctionNode helper |
    directlyInsideUnboundedLoop(invocation) and
    helper = invocation.getCalleeNode().getAFunctionValue() and
    callbackExecutesCall(helper, call)
  )
  or
  // Directly or indirectly inside an uncleared setInterval callback.
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    isUnboundedInterval(timer) and
    callback = timer.getArgument(0).getAFunctionValue() and
    callbackExecutesCall(callback, call)
  )
  or
  // Directly or indirectly inside a recursive setTimeout callback.
  insideRecursiveSetTimeout(call)
}

predicate inAnyLoop(DataFlow::CallNode call) {
  inUnboundedLoop(call) or
  directlyInsideAnyLoop(call) or
  exists(DataFlow::CallNode invocation, DataFlow::FunctionNode helper |
    directlyInsideAnyLoop(invocation) and
    helper = invocation.getCalleeNode().getAFunctionValue() and
    callbackExecutesCall(helper, call)
  ) or
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    timer = DataFlow::globalVarRef("setInterval").getACall() and
    callback = timer.getArgument(0).getAFunctionValue() and
    callbackExecutesCall(callback, call)
  ) or
  exists(DataFlow::MethodCallNode arrayCall, DataFlow::FunctionNode callback |
    arrayCall.getMethodName() in ["forEach", "map"] and
    callback = arrayCall.getArgument(0).getAFunctionValue() and
    callbackExecutesCall(callback, call)
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
      // Exact collection routes create a tag, note, resource, or folder.
      (root in ["tags", "notes", "resources", "folders"] and not exists(arr.getElement(1))) or
      // The exact ["tags", tagId, "notes"] route creates a tag-note link.
      (
        root = "tags" and
        exists(arr.getElement(1)) and
        arr.getElement(2).getStringValue() = "notes" and
        not exists(arr.getElement(3))
      )
    )
  )
}

predicate isFileWrite(DataFlow::CallNode call) {
  exists(string meth |
    meth in ["writeFile", "writeFileSync", "appendFile", "appendFileSync", "outputFile", "outputFileSync"] and
    (
      exists(string moduleName |
        moduleName in ["fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"] and
        call = DataFlow::moduleMember(moduleName, meth).getACall()
      )
      or
      exists(DataFlow::MethodCallNode methodCall |
        call = methodCall and
        isJoplinFsExtraCall(methodCall) and
        methodCall.getMethodName() = meth
      )
    )
  )
}

predicate isLargeWritePayload(DataFlow::Node payload) {
  // Check if a string literal is suspiciously large or a large Buffer is allocated.
  payload.getStringValue().length() > 10000 or
  exists(DataFlow::CallNode alloc |
    alloc = DataFlow::globalVarRef("Buffer").getAMethodCall(["alloc", "allocUnsafe"]) and
    alloc.getArgument(0).getIntValue() > 10000 and
    (payload = alloc or payload.getALocalSource() = alloc)
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
    msg = "Resource Exhaustion: The plugin is creating tags, notes, resources, folders, or tag-note links from an unbounded or background loop. Ensure loops have finite execution limits."
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
    isLargeWritePayload(call.getArgument(1)) and
    inAnyLoop(call) and
    msg = "Disk Quota Exhaustion: The plugin is writing large chunks of data to the filesystem inside a loop. Verify this is intended user-initiated behavior and won't overwhelm local storage."
  )
select call, msg
