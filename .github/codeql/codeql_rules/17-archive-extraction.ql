/**
 * @name Untrusted Archive Extraction
 * @description Extracting untrusted archives from the network can lead to malicious file overwrites.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/archive-extraction
 */
import javascript
import JoplinSources

module UntrustedArchiveConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode call | call = DataFlow::globalVarRef("fetch").getACall() and source = call) or
    exists(DataFlow::CallNode call | call.getCalleeNode().getALocalSource() = DataFlow::moduleMember("axios", "get") and source = call) or
    exists(DataFlow::CallNode call | call.getCalleeNode().getALocalSource() = DataFlow::moduleImport("axios") and source = call)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode extract, DataFlow::CallNode write, DataFlow::Node pathNode |
      extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
      pathNode = extract.getArgument(0).getALocalSource() and
      write.getCalleeName() in ["writeFile", "writeFileSync"] and
      write.getArgument(0).getALocalSource() = pathNode and
      sink = write.getArgument(1)
    )
  }
}

module UntrustedArchiveFlow = TaintTracking::Global<UntrustedArchiveConfig>;
import UntrustedArchiveFlow::PathGraph

from UntrustedArchiveFlow::PathNode source, UntrustedArchiveFlow::PathNode sink, DataFlow::CallNode extract, DataFlow::CallNode write, DataFlow::Node pathNode
where
  UntrustedArchiveFlow::flowPath(source, sink) and
  extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
  pathNode = extract.getArgument(0).getALocalSource() and
  write.getCalleeName() in ["writeFile", "writeFileSync"] and
  write.getArgument(0).getALocalSource() = pathNode and
  sink.getNode() = write.getArgument(1)
select extract, source, sink, "Unsafe Archive Extraction: An archive downloaded directly from the network is being extracted onto the local disk. \\n**Reviewer Action:** This can lead to arbitrary file overwrites. Verify that the archive source is trusted, and that the extraction logic strictly validates the archive contents before unzipping."
