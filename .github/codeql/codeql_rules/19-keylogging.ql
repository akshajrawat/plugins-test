/**
 * @name Keylogging & Silent Surveillance
 * @description Monitoring live user activity or Joplin data and exfiltrating it.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/keylogging
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isJoplinHookCallback(DataFlow::FunctionNode callback, string hookKind) {
  exists(DataFlow::MethodCallNode hook, string methodName |
    methodName = hook.getMethodName() and
    (
      hook.getReceiver().getALocalSource() = Joplin::workspace() and
      methodName in [
        "onNoteContentChange", "onNoteChange", "onNoteSelectionChange", "onSyncComplete",
        "onSyncStart", "onResourceChange", "onNoteAlarmTrigger"
      ] and
      callback = hook.getArgument(0).getAFunctionValue() and
      hookKind = methodName
      or
      hook.getReceiver().getALocalSource() = Joplin::settings() and
      methodName = "onChange" and
      callback = hook.getArgument(0).getAFunctionValue() and
      hookKind = "settings.onChange"
      or
      hook.getReceiver().getALocalSource() = Joplin::filters() and
      methodName = "on" and
      callback = hook.getArgument(1).getAFunctionValue() and
      hookKind = "filters.on"
      or
      hook.getReceiver().getALocalSource() = Joplin::editors() and
      methodName = "onUpdate" and
      callback = hook.getArgument(1).getAFunctionValue() and
      hookKind = "editors.onUpdate"
    )
  )
  or
  exists(DataFlow::MethodCallNode hook, string callbackName |
    hook.getMethodName() = "register" and
    hook.getReceiver().getALocalSource() = Joplin::editors() and
    callbackName in ["onActivationCheck", "onSetup"] and
    callback = hook.getArgument(1).getALocalSource().getAPropertyWrite(callbackName).getRhs().getAFunctionValue() and
    hookKind = callbackName
  )
}

predicate hasSensitiveJoplinHookParameter(DataFlow::FunctionNode callback) {
  exists(string hookKind |
    isJoplinHookCallback(callback, hookKind) and
    not hookKind in ["onSyncStart", "onSyncComplete", "onSetup"]
  )
}

predicate isKeyboardOrInputCallback(DataFlow::FunctionNode callback) {
  exists(DataFlow::MethodCallNode listener, string eventName |
    listener.getMethodName() in ["addEventListener", "on", "addListener"] and
    eventName = listener.getArgument(0).getStringValue() and
    eventName in ["keydown", "keyup", "keypress", "beforeinput", "input", "paste"] and
    callback = listener.getArgument(1).getAFunctionValue()
  )
}

predicate isSurveillanceCallback(DataFlow::FunctionNode callback) {
  exists(string hookKind | isJoplinHookCallback(callback, hookKind)) or
  isKeyboardOrInputCallback(callback)
}

predicate functionDirectlyCalls(DataFlow::FunctionNode caller, DataFlow::FunctionNode callee) {
  exists(DataFlow::CallNode invocation |
    invocation.getContainer() = caller.getFunction() and
    callee = invocation.getCalleeNode().getAFunctionValue()
  )
}

predicate callbackExecutesCall(DataFlow::FunctionNode callback, DataFlow::CallNode call) {
  exists(DataFlow::FunctionNode owner |
    call.getContainer() = owner.getFunction() and
    functionDirectlyCalls*(callback, owner)
  )
}

predicate isReadInsideSurveillanceCallback(DataFlow::Node source) {
  exists(DataFlow::FunctionNode callback, DataFlow::CallNode call |
    isSurveillanceCallback(callback) and
    callbackExecutesCall(callback, call) and
    (
      call.getCalleeName() in [
        "selectedNote", "selectedNoteIds", "selectedFolder", "selectedNoteHash"
      ] and
      call.getReceiver().getALocalSource() = Joplin::workspace()
      or
      call.getCalleeName() in ["get", "search"] and
      call.getReceiver().getALocalSource() = Joplin::data()
    ) and
    source = call
  )
}

module KeyloggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::FunctionNode callback |
      hasSensitiveJoplinHookParameter(callback) and
      source = callback.getParameter(0)
    )
    or
    exists(DataFlow::FunctionNode callback |
      isKeyboardOrInputCallback(callback) and
      source = callback.getParameter(0)
    )
    or
    isReadInsideSurveillanceCallback(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }
}

module KeyloggingFlow = TaintTracking::Global<KeyloggingConfig>;
import KeyloggingFlow::PathGraph

from KeyloggingFlow::PathNode source, KeyloggingFlow::PathNode sink
where KeyloggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Silent Surveillance / Keylogging: Live keyboard, input, Joplin activity, or data captured during an event is flowing to a network request. Verify that this collection and transmission is explicitly disclosed and authorized by the user."
