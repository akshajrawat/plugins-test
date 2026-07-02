/**
 * @name Clipboard Injection
 * @description Detects replacing the user's clipboard with arbitrary external data.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-injection
 */
import javascript
import JoplinSources

module ClipboardInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::clipboard().getAMethodCall("readText") or
    Joplin::isRemoteDataSource(source)
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

module ClipboardInjectionFlow = TaintTracking::Global<ClipboardInjectionConfig>;
import ClipboardInjectionFlow::PathGraph

from ClipboardInjectionFlow::PathNode source, ClipboardInjectionFlow::PathNode sink
where ClipboardInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard Hijacking Risk: The plugin is reading external remote or the user's current clipboard data and replacing the clipboard contents. Verify that this is triggered by a safe user action (like clicking a \"Copy\" button). If this happens silently in the background, it may be attempting to swap copied text."
