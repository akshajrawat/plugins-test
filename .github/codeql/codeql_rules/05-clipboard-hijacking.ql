/**
 * @name Clipboard Hijacking
 * @description Detects reading from and writing to the clipboard with external data.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-hijacking
 */
import javascript

import JoplinSources

module ClipboardHijackingConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    source = Joplin::clipboard().getAMethodCall("readText") or
    exists(DataFlow::CallNode call | call.getCalleeName() = "fetch" | source = call) or
    exists(source.getStringValue())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getReceiver().getALocalSource() = Joplin::clipboard() and
      (call.getMethodName() = "writeText" or call.getMethodName() = "writeHtml")
    |
      sink = call.getArgument(0)
    )
  }
}

module ClipboardHijackFlow = TaintTracking::Global<ClipboardHijackingConfig>;
import ClipboardHijackFlow::PathGraph

from ClipboardHijackFlow::PathNode source, ClipboardHijackFlow::PathNode sink
where ClipboardHijackFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard hijacking detected: clipboard read or written with arbitrary data."
