/**
 * @name Mass Data Destruction
 * @description Iterating through notes/folders to permanently destroy the database.
 * @kind problem
 * @problem.severity warning
 * @id joplin/mass-data-destruction
 */
import javascript
import JoplinSources

from LoopStmt loop, DataFlow::CallNode del
where
  del = Joplin::data().getAMethodCall("delete") and
  del.asExpr().getEnclosingStmt().getParentStmt*() = loop
select del, "Mass data deletion inside a loop detected."
