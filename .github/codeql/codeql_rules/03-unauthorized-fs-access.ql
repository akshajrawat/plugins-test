/**
 * @name Unauthorized FS Access
 * @description Detects unauthorized file system access outside the plugin's sandbox.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin unauthorized-fs-access
 * @id js/joplin/unauthorized-fs-access
 */
import javascript
import JoplinSources
import JoplinSinks

module FsAccessConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("__dirname") or
    source = DataFlow::globalVarRef("process").getAMethodCall("cwd") or
    source = DataFlow::globalVarRef("app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("electron", "app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("os", "homedir").getACall() or
    source = DataFlow::moduleMember("node:os", "homedir").getACall() or
    source = DataFlow::moduleMember("os", "tmpdir").getACall() or
    source = DataFlow::moduleMember("node:os", "tmpdir").getACall()
  }

  predicate isSink(DataFlow::Node sink) {
    isFileSystemPathSink(sink)
  }
}

module FsAccessFlow = TaintTracking::Global<FsAccessConfig>;
import FsAccessFlow::PathGraph

module SafeFsDestinationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir")
  }
  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode call |
      (
        call = DataFlow::moduleMember("path", "join").getACall() or
        call = DataFlow::moduleMember("path", "resolve").getACall() or
        call = DataFlow::moduleMember("node:path", "join").getACall() or
        call = DataFlow::moduleMember("node:path", "resolve").getACall()
      ) and
      node1 = call.getAnArgument() and
      node2 = call
    )
  }
  predicate isSink(DataFlow::Node sink) {
    isFileSystemPathSink(sink)
  }
}
module SafeFsDestinationFlow = TaintTracking::Global<SafeFsDestinationConfig>;

from FsAccessFlow::PathNode source, FsAccessFlow::PathNode sink, string msg, string severity
where
  FsAccessFlow::flowPath(source, sink) and
  not SafeFsDestinationFlow::flow(_, sink.getNode()) and
  (
    if source.getNode().(DataFlow::CallNode).getCalleeName() = "tmpdir"
    then (msg = "Temporary Directory Access: The plugin is writing to `os.tmpdir()`. \\n**Reviewer Action:** Check if this is a temporary file creation. If it is used for persistent writes, move it to `joplin.plugins.dataDir()`." and severity = "warning")
    else (msg = "Unauthorized File System Access: The plugin is using path-revealing variables (like `__dirname` or `process.cwd`) to write, modify, or delete files outside of the safe Joplin sandbox. \\n**Reviewer Action:** Plugins must exclusively use `joplin.plugins.dataDir()` for persistent file storage." and severity = "error")
  )
select sink.getNode(), source, sink, msg
