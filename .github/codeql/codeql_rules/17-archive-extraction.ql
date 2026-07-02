/**
 * @name Untrusted Archive Extraction
 * @description Extracting untrusted archives from the network can lead to malicious file overwrites.
 * @kind path-problem
 * @problem.severity warning
 * @id joplin/archive-extraction
 */
import javascript
import semmle.javascript.security.dataflow.RemoteFlowSources
import JoplinSources

module UntrustedArchiveConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    Joplin::isRemoteDataSource(source) or
    Joplin::isJoplinMessageSource(source)
  }

  predicate isBarrier(DataFlow::Node node) {
    // Integrity check barrier: data flows into a crypto hash update
    exists(DataFlow::MethodCallNode update |
      update.getMethodName() = "update" and
      node = update.getArgument(0)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode extract, DataFlow::Node destNode |
      extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
      destNode = extract.getArgument(1) and
      
      // Destination is not safely derived in the same context
      not exists(DataFlow::MethodCallNode dataDir |
        dataDir = Joplin::joplin().getAPropertyRead("plugins").getAMethodCall("dataDir") and
        dataDir.getContainer() = destNode.getContainer()
      ) and
      
      (
        // Flow 1: Remote data written to the file that is extracted
        exists(DataFlow::CallNode write, DataFlow::Node pathNode |
          pathNode = extract.getArgument(0).getALocalSource() and
          (
            (
              write.getCalleeName() in ["writeFile", "writeFileSync", "outputFile", "outputFileSync"] and
              write.getArgument(0).getALocalSource() = pathNode and
              sink = write.getArgument(1)
            )
            or
            (
              write = DataFlow::moduleMember("fs", "createWriteStream").getACall() and
              write.getArgument(0).getALocalSource() = pathNode and
              sink = write
            )
            or
            (
              write = DataFlow::moduleMember("fs-extra", "createWriteStream").getACall() and
              write.getArgument(0).getALocalSource() = pathNode and
              sink = write
            )
          )
        )
        or
        // Flow 2: User input directly controls the archive path
        sink = extract.getArgument(0)
      )
    )
  }
}

module UntrustedArchiveFlow = TaintTracking::Global<UntrustedArchiveConfig>;
import UntrustedArchiveFlow::PathGraph

from UntrustedArchiveFlow::PathNode source, UntrustedArchiveFlow::PathNode sink
where UntrustedArchiveFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted Archive Extraction: A remote file or user-controlled input is being downloaded and extracted to an unsafe destination. Verify that the archive source is trusted, and that the extraction logic strictly validates the archive contents before unzipping."
