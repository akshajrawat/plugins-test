/**
 * @name Semantic Integrity Sabotage (Gaslighting)
 * @description Silently modifying user notes in a malicious or destabilizing manner.
 * @kind problem
 * @problem.severity error
 * @id joplin/semantic-sabotage
 */
import javascript
import JoplinSources

from DataFlow::CallNode hook, DataFlow::FunctionNode callback, DataFlow::CallNode put
where
  (hook = Joplin::workspace().getAMethodCall("onNoteSelectionChange") or hook = Joplin::workspace().getAMethodCall("onNoteChange")) and
  callback = hook.getArgument(0).getALocalSource() and
  put.getContainer() = callback.getFunction() and
  put = Joplin::data().getAMethodCall("put") and
  put.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "notes"
select put, "Semantic Sabotage: Note modified inside workspace event hook."
