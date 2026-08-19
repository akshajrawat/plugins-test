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

predicate isPathCompositionCall(DataFlow::CallNode call) {
  call = DataFlow::moduleMember("path", "join").getACall() or
  call = DataFlow::moduleMember("path", "resolve").getACall() or
  call = DataFlow::moduleMember("node:path", "join").getACall() or
  call = DataFlow::moduleMember("node:path", "resolve").getACall()
}

// checks if funtion call are passed hardcoded traversal segments such as ".."
predicate hasParentDirectorySegment(DataFlow::CallNode call) {
  exists(string value |
    value = call.getAnArgument().getStringValue() and
    (
      value = ".." or
      value.regexpMatch("\\.\\.[/\\\\].*") or
      value.regexpMatch(".*[/\\\\]\\.\\.([/\\\\].*)?")
    )
  )
}

module DataDirTraversalConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode pathCall |
      isPathCompositionCall(pathCall) and
      hasParentDirectorySegment(pathCall) and
      sink = pathCall
    )
  }
}

module DataDirTraversalFlow = TaintTracking::Global<DataDirTraversalConfig>;

predicate isDataDirTraversal(DataFlow::Node source) {
  exists(DataFlow::CallNode pathCall, DataFlow::Node dataDir |
    isPathCompositionCall(pathCall) and
    hasParentDirectorySegment(pathCall) and
    DataDirTraversalFlow::flow(dataDir, pathCall) and
    source = pathCall
  )
}

module FsAccessConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("__dirname") or
    source = DataFlow::globalVarRef("process").getAMethodCall("cwd") or
    source = DataFlow::globalVarRef("app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("electron", "app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("@electron/remote", "app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("os", "homedir").getACall() or
    source = DataFlow::moduleMember("node:os", "homedir").getACall() or
    source = DataFlow::moduleMember("os", "tmpdir").getACall() or
    source = DataFlow::moduleMember("node:os", "tmpdir").getACall() or
    isDataDirTraversal(source)
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::CallNode call |
      isPathCompositionCall(call) and
      node1 = call.getAnArgument() and
      node2 = call
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isFileSystemPathSink(sink) and
    not isArchiveExtractionDestinationSink(sink)
  }
}

module FsAccessFlow = TaintTracking::Global<FsAccessConfig>;
import FsAccessFlow::PathGraph

from FsAccessFlow::PathNode source, FsAccessFlow::PathNode sink, string msg
where
  FsAccessFlow::flowPath(source, sink) and
  (
    if source.getNode().(DataFlow::CallNode).getCalleeName() = "tmpdir"
    then msg = "Temporary Directory Access: The plugin is writing to `os.tmpdir()`. Check if this is a temporary file creation. If it is used for persistent writes, move it to `joplin.plugins.dataDir()`."
    else msg = "Unauthorized File System Access: The plugin is using path-revealing variables (like `__dirname` or `process.cwd`) to write, modify, or delete files outside of the safe Joplin sandbox. Plugins must exclusively use `joplin.plugins.dataDir()` for persistent file storage."
  )
select sink.getNode(), source, sink, msg
