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

predicate isDestructiveValue(DataFlow::Node val) {
  not val.getStringValue() = "0" and
  not val.getStringValue() = "false"
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
  exists(DataFlow::CallNode del, DataFlow::ArrayCreationNode arr |
    del = Joplin::data().getAMethodCall("delete") and
    arr = del.getArgument(0).getALocalSource() and
    arr.getElement(0).getStringValue() = "folders" and
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
