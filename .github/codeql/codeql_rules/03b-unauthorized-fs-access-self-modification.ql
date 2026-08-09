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

predicate isCopySource(DataFlow::Node path) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() in ["copy", "copySync", "copyFile", "copyFileSync"] and
    path = call.getArgument(0)
  )
}

predicate isFileMutationTarget(DataFlow::Node path) {
  not isArchiveExtractionDestinationSink(path) and
  (
    (
      path = any(FileSystemWriteAccess access).getAPathArgument() and
      not isCopySource(path)
    ) or
    exists(DataFlow::CallNode call |
      (
        call.getCalleeName() in ["copy", "copySync", "copyFile", "copyFileSync"] and
        path = call.getArgument(1)
      ) or
      (
        call.getCalleeName() in ["move", "moveSync", "rename", "renameSync"] and
        (path = call.getArgument(0) or path = call.getArgument(1))
      ) or
      (
        call.getCalleeName() in [
          "writeFile", "writeFileSync",
          "appendFile", "appendFileSync",
          "outputFile", "outputFileSync",
          "remove", "removeSync",
          "emptyDir", "emptyDirSync",
          "ensureFile", "ensureFileSync",
          "ensureDir", "ensureDirSync",
          "unlink", "unlinkSync",
          "rm", "rmSync",
          "rmdir", "rmdirSync",
          "chmod", "chmodSync"
        ] and
        path = call.getArgument(0)
      )
    )
  )
}

predicate isPluginPackageFileName(DataFlow::Node source) {
  exists(string value |
    value = source.getStringValue() and
    value.regexpMatch("(?i)(.*[/\\\\])?(index\\.js|main\\.js|plugin\\.js|manifest\\.json|package\\.json)$")
  )
}

module SelfModConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = DataFlow::globalVarRef("__filename") or
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("installationDir")
  }
  
  predicate isSink(DataFlow::Node sink) {
    isFileMutationTarget(sink)
  }
}

module SelfModFlow = TaintTracking::Global<SelfModConfig>;
import SelfModFlow::PathGraph

module PluginPackageFileConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isPluginPackageFileName(source)
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
    isFileMutationTarget(sink)
  }
}

module PluginPackageFileFlow = TaintTracking::Global<PluginPackageFileConfig>;

from SelfModFlow::PathNode source, SelfModFlow::PathNode sink
where 
  SelfModFlow::flowPath(source, sink) and
  (
    source.getNode() = DataFlow::globalVarRef("__filename") or
    PluginPackageFileFlow::flow(_, sink.getNode())
  )
select sink.getNode(), source, sink, "Plugin Self-Modification: The plugin is attempting to overwrite or delete its own installation files. A plugin should never modify its own packaged files."
