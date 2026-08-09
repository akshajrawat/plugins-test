/**
 * @name Semantic Integrity Sabotage (Gaslighting)
 * @description Silently modifying user notes in a malicious or destabilizing manner.
 * @kind problem
 * @problem.severity error
 * @id joplin/semantic-sabotage
 */
import javascript
import JoplinSources

predicate isWorkspaceHookCallback(DataFlow::FunctionNode cb) {
  exists(DataFlow::CallNode hook |
    (
      hook = Joplin::workspace().getAMethodCall("onNoteSelectionChange") or
      hook = Joplin::workspace().getAMethodCall("onNoteChange") or
      hook = Joplin::workspace().getAMethodCall("onNoteContentChange") or
      hook = Joplin::workspace().getAMethodCall("onNoteAlarmTrigger")
    ) and
    cb = hook.getArgument(0).getAFunctionValue()
  )
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

predicate isExactNotePath(DataFlow::Node path) {
  exists(DataFlow::ArrayCreationNode arr |
    arr = path.getALocalSource() and
    arr.getElement(0).getStringValue() = "notes" and
    exists(arr.getElement(1)) and
    not exists(arr.getElement(2))
  )
}

predicate isNoteMutation(DataFlow::CallNode call) {
  // joplin.data.put/delete(["notes", noteId])
  (
    call = Joplin::data().getAMethodCall(["put", "delete"]) and
    isExactNotePath(call.getArgument(0))
  )
  or
  // joplin.commands.execute("insertText", ...) or "replaceSelection"
  exists(string cmd |
    call = Joplin::joplin().getAPropertyRead("commands").getAMethodCall("execute") and
    cmd = call.getArgument(0).getStringValue() and
    cmd in ["insertText", "replaceSelection"]
  )
}

from DataFlow::CallNode call, DataFlow::FunctionNode cb
where
  isWorkspaceHookCallback(cb) and
  isNoteMutation(call) and
  callbackExecutesCall(cb, call)
select call, "The plugin is mutating or deleting notes directly inside a workspace event hook (e.g., `onNoteSelectionChange`). Modifying a note the exact moment a user views or edits it can mimic \"gaslighting\" malware. Ensure these modifications are expected, visible formatting changes, not destructive silent edits."
