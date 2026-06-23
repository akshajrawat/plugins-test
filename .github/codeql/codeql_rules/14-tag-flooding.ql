/**
 * @name Asynchronous Tag Flooding & Search Poisoning
 * @description Sabotaging application indexing via programmatic high-volume metadata inflation.
 * @kind problem
 * @problem.severity warning
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

predicate isUnboundedInterval(DataFlow::CallNode timer) {
  timer = DataFlow::globalVarRef("setInterval").getACall() and
  not exists(DataFlow::CallNode clear |
    clear = DataFlow::globalVarRef("clearInterval").getACall() and
    clear.getArgument(0).getALocalSource() = timer.getALocalSource()
  )
}

from DataFlow::CallNode post
where
  post = Joplin::data().getAMethodCall("post") and
  isTargetPath(post.getArgument(0)) and
  (
    // Inside a setInterval loop (excluding setTimeout, focusing on intervals that aren't cleared)
    exists(DataFlow::CallNode timer, DataFlow::FunctionNode callback |
      isUnboundedInterval(timer) and
      callback = timer.getArgument(0).getALocalSource() and
      post.getContainer() = callback.getFunction()
    )
    or
    // Inside a synchronous loop (for, while, do-while)
    exists(Stmt loop |
      (loop instanceof ForStmt or loop instanceof WhileStmt or loop instanceof DoWhileStmt) and
      post.asExpr().getEnclosingStmt().getParentStmt*() = loop
    )
  )
select post, "Tag/Note Flooding: High-volume creation of items in a background loop or synchronous loop. \n" +
  "Reviewer: verify (1) loop/interval is unbounded or has a very high iteration count, (2) items created are uniquely named (index pollution) vs. repeated/idempotent, (3) interval is never cleared, (4) check for synchronous loop variants."
