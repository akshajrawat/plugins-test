/**
 * @name Clipboard Execution
 * @description Detects reading the user's clipboard and executing it as code or passing it to the terminal.
 * @kind path-problem
 * @problem.severity error
 * @tags security joplin-plugin clipboard-hijacking
 * @id js/joplin/clipboard-execution
 */
import javascript
import JoplinSources
import JoplinSinks

predicate isCodeExecutionSink(DataFlow::Node sink) {
  isCommandExecutionSink(sink) or
  exists(DataFlow::CallNode call | 
    call.getCalleeName() = "eval" or
    call.getCalleeName() = "setTimeout" or
    call.getCalleeName() = "setInterval" or
    call = DataFlow::globalVarRef("Function").getAnInstantiation()
    | sink = call.getArgument(0)
  )
}

module ClipboardExecutionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source = Joplin::clipboard().getAMethodCall("readText")
  }
  predicate isSink(DataFlow::Node sink) {
    isCodeExecutionSink(sink)
  }
}

module ClipboardExecutionFlow = TaintTracking::Global<ClipboardExecutionConfig>;
import ClipboardExecutionFlow::PathGraph

from ClipboardExecutionFlow::PathNode source, ClipboardExecutionFlow::PathNode sink
where ClipboardExecutionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Clipboard Execution Risk: The plugin is reading the user's clipboard and passing it directly into a code evaluation or terminal command sink."
