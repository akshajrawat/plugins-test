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

module UnsafeDestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // 1. process.env
    source = DataFlow::globalVarRef("process").getAPropertyRead("env") or
    // 2. __dirname
    source = DataFlow::globalVarRef("__dirname") or
    // 3. process.cwd()
    source = DataFlow::globalVarRef("process").getAMethodCall("cwd") or
    // 4. Hardcoded absolute paths
    exists(string val |
      val = source.getStringValue() and
      val.regexpMatch("^(/|~|[a-zA-Z]:\\\\).*")
    ) or
    // 5. Remote / User Input
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode extract |
      extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
      sink = extract.getArgument(1)
    )
  }
}

module UnsafeDestFlow = TaintTracking::Global<UnsafeDestConfig>;
import UnsafeDestFlow::PathGraph

from UnsafeDestFlow::PathNode source, UnsafeDestFlow::PathNode sink
where UnsafeDestFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe Extraction Destination: An archive is being extracted into an unsafe path derived from user input, system environment variables, or hardcoded absolute paths. Reject this if it risks overwriting user configuration files or core Joplin application data."
