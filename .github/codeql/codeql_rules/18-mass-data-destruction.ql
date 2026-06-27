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

predicate isUnboundedLoop(LoopStmt loop) {
  loop instanceof WhileStmt and isAlwaysTrueCondition(loop.getTest())
  or
  loop instanceof DoWhileStmt and isAlwaysTrueCondition(loop.getTest())
  or
  loop instanceof ForStmt and not exists(loop.getTest())
  or
  loop instanceof ForStmt and isAlwaysTrueCondition(loop.getTest())
}

predicate inLoop(DataFlow::CallNode call) {
  // Inside a synchronous loop with no normal finite bound.
  exists(LoopStmt loop |
    isUnboundedLoop(loop) and
    call.asExpr().getEnclosingStmt().getParentStmt*() = loop
  )
  or
  // Inside a setInterval loop
  exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
    isUnboundedInterval(timer) and
    callback = timer.getArgument(0).getALocalSource() and
    call.getContainer() = callback.getFunction()
  )
}

from DataFlow::Node node, string msg
where
  // 1. Any folder delete
  exists(DataFlow::CallNode del, DataFlow::ArrayCreationNode arr |
    del = Joplin::data().getAMethodCall("delete") and
    arr = del.getArgument(0).getALocalSource() and
    arr.getElement(0).getStringValue() = "folders" and
    node = del and
    msg = "Cascading folder deletion detected. This permanently deletes all notes within."
  )
  or
  // 2. Loop delete
  exists(DataFlow::CallNode del |
    del = Joplin::data().getAMethodCall("delete") and
    inLoop(del) and
    node = del and
    msg = "Mass data deletion inside an unbounded loop detected. Reviewer: confirm this loop is bounded by something finite (e.g. user-selected note IDs) and not an attacker-controlled or unbounded count."
  )
  or
  // 3. Loop put with soft-delete payload
  exists(DataFlow::CallNode put, DataFlow::SourceNode payload |
    put = Joplin::data().getAMethodCall("put") and
    inLoop(put) and
    payload = put.getArgument(2).getALocalSource() and
    (
      exists(payload.getAPropertyWrite("deleted_time")) or
      exists(payload.getAPropertyWrite("is_conflict"))
    ) and
    node = put and
    msg = "Mass data soft-deletion/conflict creation inside an unbounded loop detected. Reviewer: confirm this loop is bounded by something finite (e.g. user-selected note IDs) and not an attacker-controlled or unbounded count."
  )
select node, msg
