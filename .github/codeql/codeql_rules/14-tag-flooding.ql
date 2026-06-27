/**
 * @name Asynchronous Tag Flooding & Search Poisoning
 * @description Sabotaging application indexing via programmatic high-volume metadata inflation.
 * @kind problem
 * @problem.severity error
 * @id joplin/tag-flooding
 */
import javascript
import JoplinSources

predicate isTargetPath(DataFlow::Node pathArg) {
  exists(DataFlow::ArrayCreationNode arr, string val | 
    arr = pathArg.getALocalSource() and
    val = arr.getElement(0).getStringValue() and
    val in ["tags", "notes", "resources"]
  ) or
  // also catch non-literal dynamically built paths (very roughly)
  not exists(pathArg.getALocalSource().(DataFlow::ArrayCreationNode))
}


predicate isRecursiveTimeout(DataFlow::FunctionNode fn) {
  exists(DataFlow::CallNode timer |
    timer = DataFlow::globalVarRef("setTimeout").getACall() and
    timer.getContainer() = fn.getFunction() and
    timer.getArgument(0).getALocalSource() = fn
  )
}

predicate isDangerousCall(DataFlow::CallNode call) {
  (
    call = Joplin::data().getAMethodCall("post") and
    isTargetPath(call.getArgument(0))
  ) or
  exists(string meth | meth = "writeFile" or meth = "writeFileSync" |
    call = DataFlow::moduleMember("fs", meth).getACall() or
    call = DataFlow::moduleMember("fs-extra", meth).getACall()
  )
}

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

from DataFlow::CallNode post
where
  isDangerousCall(post) and
  (
    // Inside a setInterval loop (excluding setTimeout, focusing on intervals that aren't cleared)
    exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
      (isUnboundedInterval(timer) or isRecursiveTimeout(callback)) and
      callback = timer.getArgument(0).getALocalSource() and
      post.getContainer() = callback.getFunction()
    )
    or
    // Inside a synchronous loop with no normal finite bound.
    exists(LoopStmt loop |
      isUnboundedLoop(loop) and
      post.asExpr().getEnclosingStmt().getParentStmt*() = loop
    )
  )
select post, "Resource Exhaustion (Flooding): The plugin is rapidly creating tags, notes, or resources inside an unbounded background interval or synchronous loop. \\n**Reviewer Action:** This can destroy Joplin's search index and exhaust storage quotas. Confirm the loop is strictly bounded by a finite limit (e.g., iterating only over user-selected notes) and is not infinite."
