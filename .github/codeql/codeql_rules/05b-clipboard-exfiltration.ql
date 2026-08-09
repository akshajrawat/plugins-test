/**
 * @name Clipboard Exfiltration
 * @description Detects reading the user's clipboard and sending the contents over the network.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-exfiltration
 */
import javascript
import JoplinSources
import JoplinSinks

module ClipboardExfiltrationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::MethodCallNode call |
      call.getReceiver().getALocalSource() = Joplin::clipboard() and
      call.getMethodName() in ["readText", "readHtml", "readImage"] and
      source = call
    )
  }
  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }
}

module ClipboardExfiltrationFlow = TaintTracking::Global<ClipboardExfiltrationConfig>;
import ClipboardExfiltrationFlow::PathGraph

from ClipboardExfiltrationFlow::PathNode source, ClipboardExfiltrationFlow::PathNode sink
where ClipboardExfiltrationFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard Exfiltration Risk: The plugin is reading the user's clipboard and sending the contents over the network."
