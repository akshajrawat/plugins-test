/**
 * @name Plugin Self-Modification
 * @description Detects if the plugin attempts to overwrite or modify its own installed files.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin unauthorized-fs-access self-modification
 * @id js/joplin/unauthorized-fs-access-self-modification
 */
import javascript
import JoplinSources
import JoplinSinks

module SelfModConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("__dirname") or
    source = DataFlow::globalVarRef("__filename") or
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("installationDir")
  }
  
  predicate isSink(DataFlow::Node sink) {
    isFileSystemPathSink(sink)
  }
}

module SelfModFlow = TaintTracking::Global<SelfModConfig>;
import SelfModFlow::PathGraph

predicate targetsPluginFile(DataFlow::Node sink) {
  exists(Expr e |
    e.getEnclosingStmt() = sink.asExpr().getEnclosingStmt() and
    e.getStringValue().regexpMatch("(?i).*(index\\.js|main\\.js|plugin\\.js|manifest\\.json|package\\.json).*")
  )
}

from SelfModFlow::PathNode source, SelfModFlow::PathNode sink
where 
  SelfModFlow::flowPath(source, sink) and
  targetsPluginFile(sink.getNode())
select sink.getNode(), source, sink, "Plugin Self-Modification: The plugin is attempting to overwrite or delete its own installation files. A plugin should never modify its own packaged files."
