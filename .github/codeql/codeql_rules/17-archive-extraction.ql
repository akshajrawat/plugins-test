/**
 * @name Untrusted Archive Extraction
 * @description Extracting untrusted archives from the network can lead to malicious file overwrites.
 * @kind path-problem
 * @problem.severity warning
 * @id joplin/archive-extraction
 */
import javascript
import JoplinSources

module UntrustedArchiveConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" and source = call) or
    exists(DataFlow::CallNode call | call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", "get") and source = call)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode extract |
      extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
      sink = extract.getArgument(0)
    )
  }
}

module UntrustedArchiveFlow = TaintTracking::Global<UntrustedArchiveConfig>;
import UntrustedArchiveFlow::PathGraph

from UntrustedArchiveFlow::PathNode source, UntrustedArchiveFlow::PathNode sink
where UntrustedArchiveFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted archive downloaded from network is extracted."
