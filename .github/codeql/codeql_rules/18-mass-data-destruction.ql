/**
 * @name Mass Data Destruction
 * @description Iterating through notes/folders to permanently destroy the database.
 * @kind problem
 * @problem.severity error
 * @id joplin/mass-data-destruction
 */
import javascript
import JoplinSources

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
    call.asExpr().getEnclosingStmt().getParentStmt*() = loop.getBody() and
    not exists(Function nested |
      call.asExpr().getParent*() = nested and
      nested.getParent*() = loop
    )
  )
}

predicate directlyInsideAnyLoop(DataFlow::CallNode call) {
  exists(LoopStmt loop |
    call.asExpr().getEnclosingStmt().getParentStmt*() = loop.getBody() and
    not exists(Function nested |
      call.asExpr().getParent*() = nested and
      nested.getParent*() = loop
    )
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
  directlyInsideUnboundedLoop(call)
  or
  exists(DataFlow::CallNode invocation, DataFlow::FunctionNode helper |
    directlyInsideUnboundedLoop(invocation) and
    helper = invocation.getCalleeNode().getAFunctionValue() and
    callbackExecutesCall(helper, call)
  )
  or
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    isUnboundedInterval(timer) and
    callback = timer.getArgument(0).getAFunctionValue() and
    callbackExecutesCall(callback, call)
  )
  or
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
    arrayCall.getMethodName() in
      ["forEach", "map", "flatMap", "filter", "reduce", "reduceRight", "some", "every", "find", "findIndex"] and
    callback = arrayCall.getArgument(0).getAFunctionValue() and
    callbackExecutesCall(callback, call)
  )
}

predicate isExactItemPath(DataFlow::Node path, string collection) {
  exists(DataFlow::ArrayCreationNode arr |
    arr = path.getALocalSource() and
    arr.getElement(0).getStringValue() = collection and
    exists(arr.getElement(1)) and
    not exists(arr.getElement(2))
  )
}

predicate isExplicitlyInactiveValue(DataFlow::Node val) {
  val.getIntValue() = 0 or
  val.getStringValue() in ["0", "false"] or
  (
    val.asExpr().stripParens() instanceof BooleanLiteral and
    val.asExpr().stripParens().(BooleanLiteral).getBoolValue() = false
  ) or
  val.asExpr().stripParens() instanceof NullLiteral or
  val = DataFlow::globalVarRef("undefined")
}

predicate isDestructiveValue(DataFlow::Node val) {
  not isExplicitlyInactiveValue(val)
}

predicate isDestructiveBody(DataFlow::Node val) {
  val.getStringValue() = ""
}

predicate hasDestructivePayload(DataFlow::SourceNode payload) {
  (exists(DataFlow::Node val | val = payload.getAPropertyWrite("deleted_time").getRhs() and isDestructiveValue(val))) or
  (exists(DataFlow::Node val | val = payload.getAPropertyWrite("is_conflict").getRhs() and isDestructiveValue(val))) or
  (exists(DataFlow::Node val | val = payload.getAPropertyWrite("body").getRhs() and isDestructiveBody(val)))
}

from DataFlow::Node node, string msg
where
    // 1. Any folder delete
    exists(DataFlow::CallNode del |
      del = Joplin::data().getAMethodCall("delete") and
      isExactItemPath(del.getArgument(0), "folders") and
      node = del and
      msg = "Mass Data Destruction: The plugin is deleting an entire folder (which cascades to all its notes). This can permanently destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user."
    )
    or
    // 2. Unbounded loop delete
    exists(DataFlow::CallNode del |
      del = Joplin::data().getAMethodCall("delete") and
      inUnboundedLoop(del) and
      node = del and
      msg = "Mass Data Destruction: The plugin is looping unboundedly to delete many items at once. This can permanently destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user. If a loop is used, ensure it is bounded by finite, safe limits and not attacker-controlled."
    )
    or
    // 3. Any loop put with soft-delete payload
    exists(DataFlow::CallNode put, DataFlow::SourceNode payload |
      put = Joplin::data().getAMethodCall("put") and
      inAnyLoop(put) and
      payload = put.getArgument(2).getALocalSource() and
      hasDestructivePayload(payload) and
      node = put and
      msg = "Mass Data Destruction: The plugin is looping to soft-delete, wipe bodies, or flag conflicts on many items at once. This can effectively destroy the user's database. Verify this is a legitimate bulk-management feature explicitly initiated by the user. If a loop is used, ensure it is bounded by finite, safe limits and not attacker-controlled."
    )
select node, msg
