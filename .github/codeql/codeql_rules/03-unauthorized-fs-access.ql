/**
 * @name Unauthorized FS Access / Self-Modification
 * @description Detects unauthorized file system access or self-modification.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin unauthorized-fs-access
 * @id js/joplin/unauthorized-fs-access
 */
import javascript
import DataFlow::PathGraph
import JoplinSources
import JoplinSinks

class FsAccessConfig extends TaintTracking::Configuration {
  FsAccessConfig() { this = "FsAccessConfig" }

  override predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("__dirname") or
    source = DataFlow::globalVarRef("__filename") or
    source = DataFlow::globalVarRef("process").getAMethodCall("cwd") or
    source = DataFlow::globalVarRef("app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("os", "homedir").getACall() or
    source = DataFlow::moduleMember("path", "resolve").getACall() or
    source = DataFlow::moduleMember("path", "join").getACall() or
    source = Joplin::joplin().getAPropertyRead("plugins").getAPropertyRead("dataDir") or
    source = Joplin::require("fs") or
    source = Joplin::require("fs-extra") or
    source = DataFlow::moduleImport("fs") or
    source = DataFlow::moduleImport("fs-extra") or
    (source = DataFlow::globalVarRef("require").getACall() and source.(DataFlow::CallNode).getArgument(0).getStringValue().regexpMatch("fs(-extra)?"))
  }

  override predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isFileSystemPathSink(sink)
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, FsAccessConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unauthorized FS Access or Self-Modification."
