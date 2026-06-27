/**
 * @name Archive Entry Traversal
 * @description Using unsanitized archive entry names in filesystem paths can lead to path traversal vulnerabilities.
 * @kind path-problem
 * @problem.severity warning
 * @id joplin/archive-entry-traversal
 */
import javascript
import JoplinSources
import JoplinSinks

module ArchiveEntryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract")
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(DataFlow::PropRead read |
      read.getBase() = node1 and
      read.getPropertyName() in ["name", "entryName"] and
      node2 = read
    )
  }

  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isFileSystemPathSink(sink)
  }
}

module ArchiveEntryFlow = TaintTracking::Global<ArchiveEntryConfig>;
import ArchiveEntryFlow::PathGraph

from ArchiveEntryFlow::PathNode source, ArchiveEntryFlow::PathNode sink
where ArchiveEntryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Path Traversal Risk (Zip Slip): Unsanitized file names from inside an extracted archive are flowing directly into file system paths. \\n**Reviewer Action:** Ensure the plugin sanitizes archive entry names (e.g., blocking `../` sequences) before writing them to disk to prevent \"Zip Slip\" vulnerabilities from overwriting sensitive files outside the target directory."
