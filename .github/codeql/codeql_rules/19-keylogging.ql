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

predicate isJoplinHookCallback(DataFlow::FunctionNode callback) {
  exists(DataFlow::MethodCallNode hook, string methodName |
    methodName = hook.getMethodName() and
    (
      (hook.getReceiver().getALocalSource() = Joplin::workspace() and methodName in ["onNoteContentChange", "onNoteChange", "onNoteSelectionChange", "onSyncComplete", "onSyncStart", "onResourceChange", "onNoteAlarmTrigger"] and callback = hook.getArgument(0).getAFunctionValue()) or
      (hook.getReceiver().getALocalSource() = Joplin::settings() and methodName = "onChange" and callback = hook.getArgument(0).getAFunctionValue()) or
      (hook.getReceiver().getALocalSource() = Joplin::filters() and methodName = "on" and callback = hook.getArgument(1).getAFunctionValue()) or
      (hook.getReceiver().getALocalSource() = Joplin::panels() and methodName = "onMessage" and callback = hook.getArgument(1).getAFunctionValue()) or
      (hook.getReceiver().getALocalSource() = Joplin::contentScripts() and methodName = "onMessage" and callback = hook.getArgument(1).getAFunctionValue()) or
      (hook.getReceiver().getALocalSource() = Joplin::editors() and methodName in ["onUpdate", "onMessage"] and callback = hook.getArgument(1).getAFunctionValue())
    )
  ) or
  // Register editors via object literal
  exists(DataFlow::MethodCallNode hook |
    hook.getMethodName() = "register" and
    hook.getReceiver().getALocalSource() = Joplin::editors() and
    (
      callback = hook.getArgument(0).getALocalSource().getAPropertyWrite("onActivationCheck").getRhs().getAFunctionValue() or
      callback = hook.getArgument(0).getALocalSource().getAPropertyWrite("onSetup").getRhs().getAFunctionValue()
    )
  )
}

predicate isReadInsideHook(DataFlow::Node source) {
  exists(DataFlow::FunctionNode callback, DataFlow::CallNode call |
    isJoplinHookCallback(callback) and
    call.getContainer().getEnclosingContainer*() = callback.getFunction() and
    (
      (call.getCalleeName() in ["selectedNote", "selectedNoteIds"] and call.getReceiver().getALocalSource() = Joplin::workspace()) or
      (call.getCalleeName() in ["get", "search"] and call.getReceiver().getALocalSource() = Joplin::data())
    ) and
    source = call
  )
}

module KeyloggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Exfiltration of the callback parameter itself (excluding onSyncStart which has no parameters)
    exists(DataFlow::FunctionNode callback |
      isJoplinHookCallback(callback) and
      not exists(DataFlow::MethodCallNode hook | hook.getMethodName() = "onSyncStart" and callback = hook.getArgument(0).getAFunctionValue()) and
      source = callback.getParameter(0)
    ) or
    // Exfiltration of data read inside the callback
    isReadInsideHook(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }
}

module KeyloggingFlow = TaintTracking::Global<KeyloggingConfig>;
import KeyloggingFlow::PathGraph

from KeyloggingFlow::PathNode source, KeyloggingFlow::PathNode sink
where KeyloggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Silent Surveillance / Hook Exfiltration: Data captured from a workspace, settings, or sync event hook is being funneled directly to a network endpoint. \\n**Reviewer Action:** This captures live user activity (e.g., settings changes, post-sync harvesting, or editor keystrokes). Ensure the plugin has explicit user consent to transmit telemetry or data state changes, and verify the endpoint is secure."
