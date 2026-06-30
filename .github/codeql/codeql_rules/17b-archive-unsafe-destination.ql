/**
 * @name Unsafe Archive Extraction Destination
 * @description Extracting archives to paths outside the plugin's data directory can overwrite sensitive files.
 * @kind problem
 * @problem.severity error
 * @id joplin/archive-unsafe-destination
 */
import javascript
import JoplinSources

module SafeDestConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir")
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode extract |
      extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
      sink = extract.getArgument(1)
    )
  }
}

module SafeDestFlow = TaintTracking::Global<SafeDestConfig>;

from DataFlow::CallNode extract, DataFlow::Node dest
where
  extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
  dest = extract.getArgument(1) and
  not SafeDestFlow::flow(_, dest)
select extract, "Unsafe Extraction Destination: An archive is being extracted to a path outside of the plugin's isolated data directory. \\n**Reviewer Action:** Extraction paths must be strictly derived from `joplin.plugins.dataDir()`. Reject this if it risks overwriting user configuration files or core Joplin application data."
