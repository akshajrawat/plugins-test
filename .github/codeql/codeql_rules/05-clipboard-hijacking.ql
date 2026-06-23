/**
 * @name Clipboard Hijacking
 * @description Detects reading from and writing to the clipboard with external data.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-hijacking
 */
import javascript
import DataFlow::PathGraph
import JoplinSources

class ClipboardHijackingConfig extends TaintTracking::Configuration {
  ClipboardHijackingConfig() { this = "ClipboardHijackingConfig" }

  override predicate isSource(DataFlow::Node source) {
    source = Joplin::clipboard().getAMethodCall("readText") or
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" | source = call) or
    exists(source.getStringValue())
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getReceiver().getALocalSource() = Joplin::clipboard() and
      (call.getMethodName() = "writeText" or call.getMethodName() = "writeHtml")
    |
      sink = call.getArgument(0)
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, ClipboardHijackingConfig cfg
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard hijacking detected: clipboard read or written with arbitrary data."
