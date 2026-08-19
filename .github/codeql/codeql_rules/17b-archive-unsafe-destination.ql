/**
 * @name Unsafe Archive Extraction Destination
 * @description Extracting archives outside the plugin's data directory can overwrite files outside the plugin's storage boundary.
 * @kind problem
 * @problem.severity error
 * @id joplin/archive-unsafe-destination
 */
import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources
import JoplinSources
import JoplinSinks

predicate isArchiveDestination(DataFlow::Node sink) {
  isArchiveExtractionDestinationSink(sink)
}

module DataDirConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir")
  }

  predicate isSink(DataFlow::Node sink) {
    isArchiveDestination(sink) or
    sink = DataFlow::moduleMember(["path", "node:path"], "dirname").getACall()
  }
}

module DataDirFlow = TaintTracking::Global<DataDirConfig>;

predicate isDerivedFromDataDir(DataFlow::Node destination) {
  exists(DataFlow::Node dataDir | DataDirFlow::flow(dataDir, destination))
}

bindingset[value]
predicate isAbsolutePathLiteral(string value) {
  value.regexpMatch("/.*") or
  value.regexpMatch("[a-zA-Z]:[/\\\\].*") or
  value.regexpMatch("\\\\\\\\.*")
}

bindingset[value]
predicate hasParentDirectorySegment(string value) {
  value = ".." or
  value.regexpMatch("\\.\\.[/\\\\].*") or
  value.regexpMatch(".*[/\\\\]\\.\\.([/\\\\].*)?")
}

predicate isSystemOrUntrustedPathSource(DataFlow::Node source) {
  source = DataFlow::globalVarRef("process").getAPropertyRead("env") or
  source = DataFlow::globalVarRef("process").getAPropertyRead("argv") or
  source = DataFlow::globalVarRef("__dirname") or
  source = DataFlow::globalVarRef("__filename") or
  source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("installationDir") or
  source = DataFlow::globalVarRef("process").getAMethodCall("cwd") or
  source = DataFlow::moduleMember(["os", "node:os"], ["homedir", "tmpdir"]).getACall() or
  source = DataFlow::moduleMember(
    ["electron", "electron/main", "electron/renderer", "electron/common"], "app"
  ).getAMethodCall("getPath") or
  source = DataFlow::moduleMember("@electron/remote", "app").getAMethodCall("getPath") or
  source = Joplin::settings().getAMethodCall(["value", "values"]) or
  Joplin::isJoplinMessageSource(source) or
  source instanceof RemoteFlowSource or
  exists(DataFlow::CallNode dirname, DataFlow::Node dataDir |
    dirname = DataFlow::moduleMember(["path", "node:path"], "dirname").getACall() and
    DataDirFlow::flow(dataDir, dirname) and
    source = dirname
  )
}

predicate isUnsafeLiteralSource(DataFlow::Node source) {
  exists(string value |
    value = source.getStringValue() and
    value != "" and
    (isAbsolutePathLiteral(value) or hasParentDirectorySegment(value))
  )
}

predicate isRelativeLiteralSource(DataFlow::Node source) {
  exists(string value |
    value = source.getStringValue() and
    value != "" and
    not isAbsolutePathLiteral(value) and
    not hasParentDirectorySegment(value)
  )
}

module UnsafeDestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isSystemOrUntrustedPathSource(source) or
    isUnsafeLiteralSource(source) or
    isRelativeLiteralSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isArchiveDestination(sink)
  }
}

module UnsafeDestFlow = TaintTracking::Global<UnsafeDestConfig>;

predicate isUnsafeDestination(DataFlow::Node destination) {
  exists(DataFlow::Node source |
    UnsafeDestFlow::flow(source, destination) and
    (
      isSystemOrUntrustedPathSource(source) or
      isUnsafeLiteralSource(source) or
      (isRelativeLiteralSource(source) and not isDerivedFromDataDir(destination))
    )
  )
}

from DataFlow::Node destination
where
  isArchiveDestination(destination) and
  isUnsafeDestination(destination)
select destination, "Unsafe Extraction Destination: The archive destination is outside `joplin.plugins.dataDir()`, escapes it through parent traversal, or is controlled by an untrusted source. Use `dataDir()` with fixed child path segments and reject destinations that can escape that directory."
