/**
 * @name Data Exfiltration
 * @description Detects bulk-reading notes or resources and piping the data to network requests.
 * @kind path-problem
 * @problem.severity warning
 * @tags security joplin-plugin data-exfiltration
 * @id js/joplin/data-exfiltration
 */
import javascript
import JoplinSources
import JoplinSinks

module DataExfilConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode getCall, DataFlow::ArrayCreationNode pathArg, string typeVal |
      getCall = Joplin::data().getAMethodCall("get") and
      pathArg = getCall.getArgument(0).getALocalSource() and
      typeVal = pathArg.getElement(0).getStringValue() and
      (typeVal = "notes" or typeVal = "folders" or typeVal = "resources") and
      pathArg.getSize() = 1 and
      source = getCall
    )
    or
    exists(DataFlow::MethodCallNode selectedNoteCall |
      selectedNoteCall.getMethodName() = "selectedNote" and
      selectedNoteCall.getReceiver().getALocalSource() = Joplin::workspace() and
      source = selectedNoteCall
    )
  }

  predicate isSink(DataFlow::Node sink) {
    isNetworkExfiltrationSink(sink)
  }
}

module DataExfil = TaintTracking::Global<DataExfilConfig>;
import DataExfil::PathGraph

from DataExfil::PathNode source, DataExfil::PathNode sink
where DataExfil::flowPath(source, sink)
select sink.getNode(), source, sink, "Data Exfiltration Warning: The plugin is executing a bulk-read of notes, folders, or resources, and immediately sending that data to an external network request. \\n**Reviewer Action:** Check if the plugin is a legitimate sync/export tool. If not, this is a massive privacy breach. Verify exactly what data is being sent in the payload and ensure the destination server is trusted and expected by the user."

