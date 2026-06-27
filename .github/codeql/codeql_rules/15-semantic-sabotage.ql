/**
 * @name Semantic Integrity Sabotage (Gaslighting)
 * @description Silently modifying user notes in a malicious or destabilizing manner.
 * @kind path-problem
 * @problem.severity error
 * @id joplin/semantic-sabotage
 */
import javascript
import JoplinSources

module SemanticSabotageConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode hook, DataFlow::FunctionNode callback |
      (
        hook = Joplin::workspace().getAMethodCall("onNoteSelectionChange") or 
        hook = Joplin::workspace().getAMethodCall("onNoteChange") or
        hook = Joplin::workspace().getAMethodCall("onNoteContentChange")
      ) and
      callback = hook.getArgument(0).getALocalSource() and
      source = callback.getParameter(0)
    )
  }
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode put |
      (
        put = Joplin::data().getAMethodCall("put") or
        put = Joplin::data().getAMethodCall("delete")
      ) and
      put.getArgument(0).getALocalSource().(DataFlow::ArrayCreationNode).getElement(0).getStringValue() = "notes" and
      sink = put.getAnArgument()
    )
  }
}
module SemanticSabotageFlow = TaintTracking::Global<SemanticSabotageConfig>;
import SemanticSabotageFlow::PathGraph

from SemanticSabotageFlow::PathNode source, SemanticSabotageFlow::PathNode sink
where SemanticSabotageFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Semantic Sabotage: The plugin is silently modifying or deleting notes directly inside a workspace event hook (like `onNoteSelectionChange`). \\n**Reviewer Action:** Modifying a note the exact moment a user clicks on it is highly suspicious and mimics \"gaslighting\" malware. Ensure these modifications are expected, visible formatting changes (like an auto-linter), not destructive silent edits."
