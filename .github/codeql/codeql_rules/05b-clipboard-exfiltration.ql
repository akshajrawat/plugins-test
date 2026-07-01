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
    source = Joplin::clipboard().getAMethodCall("readText")
  }
  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }
}

module ClipboardExfiltrationFlow = TaintTracking::Global<ClipboardExfiltrationConfig>;
import ClipboardExfiltrationFlow::PathGraph

from ClipboardExfiltrationFlow::PathNode source, ClipboardExfiltrationFlow::PathNode sink
where ClipboardExfiltrationFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard Exfiltration Risk: The plugin is reading the user's clipboard and sending the contents over the network. \\n**Reviewer Action:** This is a severe privacy violation. Verify why the plugin needs to transmit clipboard contents and ensure the user explicitly authorized this data transfer."
