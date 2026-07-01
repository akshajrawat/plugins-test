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

predicate callInsideCallback(DataFlow::CallNode call, DataFlow::FunctionNode cb) {
  call.getContainer().getEnclosingContainer*() = cb.getFunction()
}

predicate isNoteMutation(DataFlow::CallNode call) {
  // joplin.data.put/delete(["notes", ...])
  exists(DataFlow::ArrayCreationNode arr |
    call = Joplin::data().getAMethodCall(["put", "delete"]) and
    arr = call.getArgument(0).getALocalSource() and
    arr.getElement(0).getStringValue() = "notes"
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
  callInsideCallback(call, cb)
select call, "Semantic Sabotage: The plugin is mutating or deleting notes directly inside a workspace event hook (e.g., `onNoteSelectionChange`). \\n**Reviewer Action:** Modifying a note the exact moment a user views or edits it can mimic \"gaslighting\" malware. Ensure these modifications are expected, visible formatting changes (like an auto-linter), not destructive silent edits."
