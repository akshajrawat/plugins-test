/**
 * @name Unauthorized FS Access / Self-Modification
 * @description Detects unauthorized file system access or self-modification.
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

  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isFileSystemPathSink(sink)
  }
}

module FsAccessFlow = TaintTracking::Global<FsAccessConfig>;
import FsAccessFlow::PathGraph

module SafeFsDestinationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir") or
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("installationDir") or
    source = DataFlow::moduleMember("os", "tmpdir").getACall() or
    source = DataFlow::moduleMember("node:os", "tmpdir").getACall()
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
    JoplinSinks::isFileSystemPathSink(sink)
  }
}

module SafeFsDestinationFlow = TaintTracking::Global<SafeFsDestinationConfig>;

from FsAccessFlow::PathNode source, FsAccessFlow::PathNode sink
where
  FsAccessFlow::flowPath(source, sink) and
  not SafeFsDestinationFlow::flow(_, sink.getNode())
select sink.getNode(), source, sink, "Unauthorized File System Access: The plugin is using path-revealing variables (like `__dirname` or `process.cwd`) to write, modify, or delete files outside of the safe Joplin sandbox. \\n**Reviewer Action:** Plugins must exclusively use `joplin.plugins.dataDir()` for file storage. Reject this if it is attempting to modify the plugin's own source files or blindly access the user's broader OS file system."
