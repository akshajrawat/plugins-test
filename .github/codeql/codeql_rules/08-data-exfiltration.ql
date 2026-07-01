/**
 * @name Data Exfiltration
 * @description Detects reading notes, folders, or resources and piping the data to network requests.
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
    exists(DataFlow::CallNode getCall, string typeVal |
      getCall = Joplin::data().getAMethodCall("get") and
      exists(DataFlow::ArrayCreationNode arr |
        arr = getCall.getArgument(0).getALocalSource() and
        typeVal = arr.getElement(0).getStringValue()
      ) and
      (typeVal = "notes" or typeVal = "folders" or typeVal = "resources") and
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
    isNetworkExfiltrationSink(sink) and
    not exists(ClientRequest cr |
      (sink = cr.getADataNode() or sink = cr.getUrl()) and
      cr.getUrl().getStringValue().regexpMatch("(?i).*(localhost|127\\.0\\.0\\.1).*")
    )
  }
}

module DataExfil = TaintTracking::Global<DataExfilConfig>;
import DataExfil::PathGraph

from DataExfil::PathNode source, DataExfil::PathNode sink
where DataExfil::flowPath(source, sink)
select sink.getNode(), source, sink, "Data Exfiltration Warning: The plugin is reading notes, folders, or resources and sending that data to an external network endpoint. \\n**Reviewer Action:** Check if the plugin is a legitimate sync/export tool. If not, this is a massive privacy breach. Verify exactly what data is being sent in the payload and ensure the destination server is trusted and expected by the user."
