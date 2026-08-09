/**
 * @name Clipboard Injection
 * @description Detects replacing the user's clipboard with remote data or existing clipboard content.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-injection
 */
import javascript
import JoplinSources

module ClipboardInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::MethodCallNode call |
      call.getReceiver().getALocalSource() = Joplin::clipboard() and
      call.getMethodName() in ["readText", "readHtml", "readImage"] and
      source = call
    ) or
    Joplin::isRemoteDataSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode call |
      call.getReceiver().getALocalSource() = Joplin::clipboard() and
      call.getMethodName() in ["writeText", "writeHtml", "writeImage", "write"]
    |
      sink = call.getArgument(0)
    )
  }
}

module ClipboardInjectionFlow = TaintTracking::Global<ClipboardInjectionConfig>;
import ClipboardInjectionFlow::PathGraph

from ClipboardInjectionFlow::PathNode source, ClipboardInjectionFlow::PathNode sink
where ClipboardInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard Hijacking Risk: The plugin is writing remote data or existing clipboard content back to the user's clipboard. Verify that this is triggered by a deliberate user action (like clicking a \"Copy\" button). If this happens silently in the background, it may be attempting to replace copied content."
