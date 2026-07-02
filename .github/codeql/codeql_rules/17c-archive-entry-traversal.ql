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
    exists(DataFlow::MethodCallNode extract |
      extract = Joplin::joplin().getAPropertyRead("fs").getAMethodCall("archiveExtract") and
      source = extract
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // 1. Explicit sanitization using path.basename
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "basename" and
      call.getReceiver().getALocalSource() = DataFlow::moduleImport("path") and
      node = call
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Await
    exists(DataFlow::PropRead await |
      await.getPropertyName() = "await" and
      await.getBase() = node1 and
      node2 = await
    )
    or
    // Promise.then
    exists(DataFlow::MethodCallNode thenCall, DataFlow::FunctionNode callback |
      thenCall.getMethodName() = "then" and
      thenCall.getReceiver() = node1 and
      callback = thenCall.getArgument(0).getAFunctionValue() and
      node2 = callback.getParameter(0)
    )
    or
    // Array element access
    exists(DataFlow::PropRead read |
      read.getBase() = node1 and
      node2 = read
    )
    or
    // Array forEach / map / for-of
    exists(DataFlow::MethodCallNode iter, DataFlow::FunctionNode callback |
      iter.getMethodName() in ["forEach", "map"] and
      iter.getReceiver() = node1 and
      callback = iter.getArgument(0).getAFunctionValue() and
      node2 = callback.getParameter(0)
    )
    or
    // Object property extraction (name, entryName)
    exists(DataFlow::PropRead read |
      read.getBase() = node1 and
      read.getPropertyName() in ["name", "entryName"] and
      node2 = read
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isFileSystemPathSink(sink) or
    isCommandExecutionSink(sink)
  }
}

module ArchiveEntryFlow = TaintTracking::Global<ArchiveEntryConfig>;
import ArchiveEntryFlow::PathGraph

from ArchiveEntryFlow::PathNode source, ArchiveEntryFlow::PathNode sink
where ArchiveEntryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Path Traversal Risk (Zip Slip): Unsanitized file names from an extracted archive are flowing directly into file system paths or command execution. Ensure the plugin sanitizes archive entry names before writing them to disk to prevent \"Zip Slip\" vulnerabilities from overwriting sensitive files outside the target directory."
