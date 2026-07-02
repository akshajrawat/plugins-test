/**
 * @name Hardcoded Config Targeting
 * @description Detects hardcoded file operations targeting sensitive paths like Joplin databases or SSH keys.
 * @kind problem
 * @problem.severity error
 * @tags security joplin-plugin unauthorized-fs-access
 * @id js/joplin/unauthorized-fs-access-config-literal
 */
import javascript
import JoplinSinks

predicate targetsConfigLiteral(DataFlow::Node sink) {
  exists(Expr e |
    e.getEnclosingStmt() = sink.asExpr().getEnclosingStmt() and
    e.getStringValue().regexpMatch("(?i).*(\\.config[\\\\/]joplin-desktop|database\\.sqlite|\\.ssh|id_rsa|authorized_keys).*")
  )
}

from DataFlow::Node sink
where
  isFileSystemPathSink(sink) and
  targetsConfigLiteral(sink)
select sink, "Sensitive Path Targeting: The plugin contains a hardcoded operation targeting a sensitive user configuration or database path. This is a severe threat indicator for data theft or tampering the data. Verify this immediately."
