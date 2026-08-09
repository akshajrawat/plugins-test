/**
 * @name Unsafe Archive Extraction Destination
 * @description Extracting archives to paths outside the plugin's data directory can overwrite sensitive files.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/archive-unsafe-destination
 */
import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources
import JoplinSources
import JoplinSinks

module UnsafeDestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 1. process.env
    source = DataFlow::globalVarRef("process").getAPropertyRead("env") or
    // 2. __dirname
    source = DataFlow::globalVarRef("__dirname") or
    source = DataFlow::globalVarRef("__filename") or
    // 3. Plugin installation directory
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("installationDir") or
    // 4. process.cwd()
    source = DataFlow::globalVarRef("process").getAMethodCall("cwd") or
    // 5. Home, temporary, and Electron application paths
    source = DataFlow::moduleMember("os", "homedir").getACall() or
    source = DataFlow::moduleMember("node:os", "homedir").getACall() or
    source = DataFlow::moduleMember("os", "tmpdir").getACall() or
    source = DataFlow::moduleMember("node:os", "tmpdir").getACall() or
    source = DataFlow::globalVarRef("app").getAMethodCall("getPath") or
    source = DataFlow::moduleMember("electron", "app").getAMethodCall("getPath") or
    // 6. Hardcoded absolute paths
    exists(string val |
      val = source.getStringValue() and
      val.regexpMatch("^(/|~|[a-zA-Z]:\\\\).*")
    ) or
    // 7. Remote / User Input
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    isArchiveExtractionDestinationSink(sink)
  }
}

module UnsafeDestFlow = TaintTracking::Global<UnsafeDestConfig>;
import UnsafeDestFlow::PathGraph

from UnsafeDestFlow::PathNode source, UnsafeDestFlow::PathNode sink
where UnsafeDestFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe Extraction Destination: An archive is being extracted into an unsafe path derived from user input, system paths, environment variables, or hardcoded absolute paths. Reject this if it risks overwriting user configuration files or core Joplin application data."
