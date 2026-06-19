/**
 * @name Keylogging & Silent Surveillance
 * @description Monitoring user notes and exfiltrating data.
 * @kind problem
 * @problem.severity error
 * @id joplin/keylogging
 */
import javascript
import JoplinSources

from DataFlow::MethodCallNode hook, DataFlow::FunctionNode callback, DataFlow::CallNode networkCall
where
  (hook.getMethodName() = "onNoteContentChange" or hook.getMethodName() = "onNoteChange") and
  hook.getReceiver().(DataFlow::PropRead).getPropertyName() = "workspace" and
  callback = hook.getArgument(0).getALocalSource() and
  networkCall.getContainer() = callback.getFunction() and
  (networkCall.getCalleeName() = "fetch" or networkCall.getCalleeName() = "axios")
select networkCall, "Keylogging: Network call inside a note change event handler."
