/**
 * @name Keylogging & Silent Surveillance
 * @description Monitoring user notes and exfiltrating data.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/keylogging
 */
import javascript
import JoplinSources
import JoplinSinks

module KeyloggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::MethodCallNode hook, DataFlow::FunctionNode callback, string receiverName, string methodName |
      hook.getReceiver().(DataFlow::PropRead).getPropertyName() = receiverName and
      methodName = hook.getMethodName() and
      (
        (receiverName = "workspace" and methodName in ["onNoteContentChange", "onNoteChange", "onNoteSelectionChange", "onSyncComplete", "onSyncStart", "onResourceChange", "onNoteAlarmTrigger"]) or
        (receiverName = "settings" and methodName = "onChange") or
        (receiverName = "editor" and methodName = "onUpdate") or
        (receiverName = "filters" and methodName = "on") or
        (receiverName in ["editor", "panels", "contentScripts"] and methodName = "onMessage")
      ) and
      callback = hook.getAnArgument().getALocalSource()
    |
      source = callback.getParameter(0)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    JoplinSinks::isNetworkExfiltrationSink(sink)
  }
}

module KeyloggingFlow = TaintTracking::Global<KeyloggingConfig>;
import KeyloggingFlow::PathGraph

from KeyloggingFlow::PathNode source, KeyloggingFlow::PathNode sink
where KeyloggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Silent Surveillance / Hook Exfiltration: Data captured from a workspace, settings, or sync event hook is being funneled directly to a network endpoint. \\n**Reviewer Action:** This captures live user activity (e.g., settings changes, post-sync harvesting, or editor keystrokes). Ensure the plugin has explicit user consent to transmit telemetry or data state changes, and verify the endpoint is secure."
