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
import JoplinSinks

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

module ClipboardNetworkConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::clipboard().getAMethodCall("readText")
  }
  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isNetworkExfiltrationSink(sink)
  }
}

module CombinedClipboardConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    ClipboardHijackingConfig::isSource(source) or ClipboardNetworkConfig::isSource(source)
  }
  predicate isSink(DataFlow::Node sink) {
    ClipboardHijackingConfig::isSink(sink) or ClipboardNetworkConfig::isSink(sink)
  }
}

module ClipboardHijackFlow = TaintTracking::Global<CombinedClipboardConfig>;
import ClipboardHijackFlow::PathGraph

from ClipboardHijackFlow::PathNode source, ClipboardHijackFlow::PathNode sink, DataFlow::Node sourceNode, DataFlow::Node sinkNode, string msg
where 
  ClipboardHijackFlow::flowPath(source, sink) and
  sourceNode = source.getNode() and
  sinkNode = sink.getNode() and
  (
    (
      ClipboardHijackingConfig::isSource(sourceNode) and
      ClipboardHijackingConfig::isSink(sinkNode) and
      msg = "Clipboard Hijacking Risk: The plugin is reading the user's clipboard and replacing it with arbitrary external data or hardcoded strings. \\n**Reviewer Action:** Verify that this is triggered by a deliberate user action (like clicking a \"Copy\" button). If this happens silently in the background, it may be attempting to swap copied text (e.g., injecting cryptocurrency wallet addresses or malicious URLs)."
    )
    or
    (
      ClipboardNetworkConfig::isSource(sourceNode) and
      ClipboardNetworkConfig::isSink(sinkNode) and
      msg = "Clipboard Exfiltration Risk: The plugin is reading the user's clipboard and sending the contents over the network. \\n**Reviewer Action:** This is a severe privacy violation. Verify why the plugin needs to transmit clipboard contents and ensure the user explicitly authorized this data transfer."
    )
  )
select sinkNode, source, sink, msg
