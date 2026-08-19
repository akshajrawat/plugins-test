/**
 * @name Untrusted Archive Extraction
 * @description Extracting an archive obtained from an untrusted source can expose the plugin to malicious archive content.
 * @kind path-problem
 * @problem.severity warning
 * @id joplin/archive-extraction
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isArchiveExtractCall(DataFlow::CallNode extract) {
  extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract")
}

predicate isArchiveFileWrite(
  DataFlow::CallNode write, DataFlow::Node path, DataFlow::Node content
) {
  exists(string method |
    method in ["writeFile", "writeFileSync", "outputFile", "outputFileSync"] and
    (
      exists(string moduleName |
        moduleName in ["fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"] and
        write = DataFlow::moduleMember(moduleName, method).getACall()
      )
      or
      exists(DataFlow::MethodCallNode methodCall |
        write = methodCall and
        isJoplinFsExtraCall(methodCall) and
        methodCall.getMethodName() = method
      )
    ) and
    path = write.getArgument(0) and
    content = write.getArgument(1)
  )
}

predicate isArchiveWriteStream(DataFlow::CallNode stream, DataFlow::Node path) {
  exists(string moduleName |
    moduleName in ["fs", "node:fs", "fs-extra"] and
    stream = DataFlow::moduleMember(moduleName, "createWriteStream").getACall()
  ) and
  path = stream.getArgument(0)
  or
  exists(DataFlow::MethodCallNode methodCall |
    stream = methodCall and
    isJoplinFsExtraCall(methodCall) and
    methodCall.getMethodName() = "createWriteStream" and
    path = methodCall.getArgument(0)
  )
}

predicate isWebReadableConversion(DataFlow::Node stream, DataFlow::Node content) {
  exists(DataFlow::MethodCallNode fromWeb |
    fromWeb = stream.getALocalSource() and
    fromWeb.getMethodName() = "fromWeb" and
    fromWeb.getReceiver().getALocalSource() =
      DataFlow::moduleMember(["stream", "node:stream"], "Readable") and
    content = fromWeb.getArgument(0)
  )
}

predicate getArchiveStreamContent(DataFlow::Node stream, DataFlow::Node content) {
  isWebReadableConversion(stream, content) or
  (
    not exists(DataFlow::Node converted | isWebReadableConversion(stream, converted)) and
    content = stream
  )
}

predicate isArchiveStreamWrite(DataFlow::Node content, DataFlow::Node path) {
  exists(DataFlow::MethodCallNode pipe, DataFlow::CallNode output |
    pipe.getMethodName() = "pipe" and
    isArchiveWriteStream(output, path) and
    pipe.getArgument(0).getALocalSource() = output.getALocalSource() and
    getArchiveStreamContent(pipe.getReceiver(), content)
  )
  or
  exists(DataFlow::CallNode pipeline, DataFlow::CallNode output, string moduleName |
    moduleName in ["stream", "node:stream", "stream/promises", "node:stream/promises"] and
    pipeline = DataFlow::moduleMember(moduleName, "pipeline").getACall() and
    output.getALocalSource() = pipeline.getArgument(1).getALocalSource() and
    isArchiveWriteStream(output, path) and
    getArchiveStreamContent(pipeline.getArgument(0), content)
  )
}

predicate writesArchiveContent(DataFlow::Node content, DataFlow::Node path) {
  exists(DataFlow::CallNode write | isArchiveFileWrite(write, path, content)) or
  isArchiveStreamWrite(content, path)
}

module ArchivePathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode write, DataFlow::Node path, DataFlow::Node content |
      isArchiveFileWrite(write, path, content) and
      source = path.getALocalSource()
    )
    or
    exists(DataFlow::Node content, DataFlow::Node path |
      isArchiveStreamWrite(content, path) and
      source = path.getALocalSource()
    )
    or
    exists(DataFlow::CallNode extract |
      isArchiveExtractCall(extract) and
      source = extract.getArgument(0).getALocalSource()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode write, DataFlow::Node content |
      isArchiveFileWrite(write, sink, content)
    )
    or
    exists(DataFlow::Node content | isArchiveStreamWrite(content, sink))
    or
    exists(DataFlow::CallNode extract |
      isArchiveExtractCall(extract) and
      sink = extract.getArgument(0)
    )
  }
}

module ArchivePathFlow = DataFlow::Global<ArchivePathConfig>;

predicate sameArchivePath(DataFlow::Node writtenPath, DataFlow::Node extractedPath) {
  writtenPath = extractedPath or
  writtenPath.getALocalSource() = extractedPath.getALocalSource() or
  exists(string pathValue |
    pathValue = writtenPath.getStringValue() and
    pathValue = extractedPath.getStringValue()
  ) or
  exists(DataFlow::Node origin |
    ArchivePathFlow::flow(origin, writtenPath) and
    ArchivePathFlow::flow(origin, extractedPath)
  )
}

module UntrustedArchiveConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    Joplin::isRemoteDataSource(source) or
    Joplin::isJoplinMessageSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    // Untrusted content is saved to a file that is later extracted.
    exists(
      DataFlow::Node writtenPath,
      DataFlow::Node extractedPath,
      DataFlow::CallNode extract
    |
      writesArchiveContent(sink, writtenPath) and
      isArchiveExtractCall(extract) and
      extractedPath = extract.getArgument(0) and
      sameArchivePath(writtenPath, extractedPath)
    )
    or
    // A webview message or remote value directly controls the archive path.
    exists(DataFlow::CallNode extract |
      isArchiveExtractCall(extract) and
      sink = extract.getArgument(0)
    )
  }
}

module UntrustedArchiveFlow = TaintTracking::Global<UntrustedArchiveConfig>;
import UntrustedArchiveFlow::PathGraph

from UntrustedArchiveFlow::PathNode source, UntrustedArchiveFlow::PathNode sink
where UntrustedArchiveFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Untrusted Archive Extraction: An archive obtained from a remote or webview-controlled source is being extracted. Confirm its origin and verify it against a trusted expected hash or digital signature before extraction. Destination safety is reviewed separately by the archive-destination rule."
